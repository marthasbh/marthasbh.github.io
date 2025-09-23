---
layout: post
title: Truffle Shuffle Update
categories: [content, project, scripts, macos]
---

While taking a DFIR course on Mac specific forensics recently, I was introduced to the truffle-shuffle script. It's a short script that pulls from MacOS' document recovery databases to reconstruct files that were autosaved by the system. The script was written five years ago and wasn't working. I decided to fork and update it as a fun side project. It's published to my github, but for those unfamiliar with the files and databases that this runs with, I have included an overview of the script, it's functionality, and how to get it working for you.

## Obtaining Necessary Files

This script requires three inputs.

1. Desired Output Directory
2. ChunkStoreDatabase
3. ChunkStorage

The files are located in the .DocumentRevisions-V100/.cs directory and require elevated privileges to access. You can either run the script as sudo or make copies of the CSChunk files and change their permissions before running the script.

The script works by reconstructing recovery files stored by MacOS as part of their built in document recovery capabilities. It reads chunk lists from the CSStorageChunkListTable in ChunkStoreDatabase. It then uses the chunk IDs to look up the offsets and sizes of these chunks in the CSChunkTable, then pulls the actual chunk bytes from the binary ChunkStorage file. It stitches those chunks together in the correct order to rebuild the original file contents, while also saving each individual raw chunk as it's own file for reference.

To determine which application should be used to open the reconstructed file, run {% highlight c %} file <reconstructedfilename> {% endhighlight %} in your terminal to get the file type.

### Script!!

{% highlight c %}
#!/usr/bin/env python3

import os
import sqlite3
from argparse import ArgumentParser
import struct
import sys

parser = ArgumentParser()
parser.add_argument("-c", "--csfile", help="ChunkStorage File")
parser.add_argument("-d", "--csdb",   help="ChunkStoreDatabase SQLite File")
parser.add_argument("-o", "--outdir", help="Output folder", default="Output")
options = parser.parse_args()

try:
   if not os.path.exists(options.outdir):
      os.makedirs(options.outdir)
except OSError as err:
   print(f"OS error - {str(err)}")
   sys.exit(1)

# open ChunkStoreDatabase and ChunkStorage file
with sqlite3.connect(options.csdb) as db:
    with open(options.csfile, 'rb') as cs:
        try:
            # Extracting chunk lists
            for row in db.execute('SELECT clt_rowid,clt_inode,clt_count,clt_chunkRowIDs FROM CSStorageChunkListTable'):
                clt_rowid, clt_inode, clt_count, clt_chunkRowIDs = row
                filename = f"{options.outdir}/{clt_inode}-{clt_rowid}"
                number_of_chunks = len(clt_chunkRowIDs)//8

                # Sanity check
                if number_of_chunks != clt_count:
                    print("WARNING: number of chunks inconsistent!")

                # Open output file            
                with open(filename, 'wb') as output:
                
                    for i in range(len(clt_chunkRowIDs)//8):
                        (chunk_id,) = struct.unpack("<Q",clt_chunkRowIDs[i*8:i*8+8])

                        # Extracting chunks
                        for [offset, dataLen, cid] in db.execute("SELECT offset,dataLen,cid from CSChunkTable where ct_rowid = ?", (chunk_id,)):
                            filenameraw = f"{options.outdir}/{clt_inode}-{clt_rowid}-{chunk_id}-raw" 
                            print(filenameraw)

                            # Append the actual chunk data to the output file
                            cs.seek(offset + 25)
                            chunkData = cs.read(dataLen - 25)
                            output.write(chunkData)

                            # Write the chunk data with header to the RAW output file
                            cs.seek(offset)
                            chunkDataRaw = cs.read(dataLen)

                            # Sanity checks
                            if struct.unpack(">l", chunkDataRaw[0:4])[0] != dataLen:
                                print("WARNING: Chunk size inconsistent!")

                            if chunkDataRaw[4:25].hex() != cid.hex():
                                print("WARNING: Chunk ID inconsistent!")

                            with open(filenameraw,'wb') as outputraw:
                                outputraw.write(chunkDataRaw)


        except sqlite3.Error as err:
            print(f"SQLite error - {str(err)}")
            sys.exit(1)



{% endhighlight %}



