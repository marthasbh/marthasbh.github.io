---
layout: post
title: Truffle Shuffle Update
categories: [content, project, scripts, macos]
---

While taking a DFIR course on Mac specific forensics recently, I was introduced to the truffle-shuffle script. It's a short script that pulls from MacOS' document recovery databases to reconstruct files that were autosaved by the system. The script was written five years ago and wasn't working. I decided to fork and update it as a fun side project. It's published to my github, but for those unfamiliar with the files and databases that this runs with, I have included an overview of the script, it's functionality, and how to get it working for you.

## Obtaining Necessary Files

This script requires three inputs.

1. Output Directory
2. CSChunkFile
3. CSChunkFileDB

The CSChunk files are located in hidden directories and require elevated privileges to access. You can either run the script as sudo or make copies of the CSChunk files and change their permissions before running the script.


## Another great heading (h2)

Lorem ipsum dolor sit amet, consectetur adipiscing elit. Fusce bibendum neque eget nunc mattis eu sollicitudin enim tincidunt. Vestibulum lacus tortor, ultricies id dignissim ac, bibendum in velit.

### Some great subheading (h3)

Proin convallis mi ac felis pharetra aliquam. Curabitur dignissim accumsan rutrum. In arcu magna, aliquet vel pretium et, molestie et arcu. Mauris lobortis nulla et felis ullamcorper bibendum.

Phasellus et hendrerit mauris. Proin eget nibh a massa vestibulum pretium. Suspendisse eu nisl a ante aliquet bibendum quis a nunc.

### Some great subheading (h3)

Praesent varius interdum vehicula. Aenean risus libero, placerat at vestibulum eget, ultricies eu enim. Praesent nulla tortor, malesuada adipiscing adipiscing sollicitudin, adipiscing eget est.

> This quote will *change* your life. It will reveal the <i>secrets</i> of the universe, and all the wonders of humanity. Don't <em>misuse</em> it.

Lorem ipsum dolor sit amet, consectetur adipiscing elit. Fusce bibendum neque eget nunc mattis eu sollicitudin enim tincidunt.

### Some great subheading (h3)

Vestibulum lacus tortor, ultricies id dignissim ac, bibendum in velit. Proin convallis mi ac felis pharetra aliquam. Curabitur dignissim accumsan rutrum.

In arcu magna, aliquet vel pretium et, molestie et arcu. Mauris lobortis nulla et felis ullamcorper bibendum. Phasellus et hendrerit mauris.

#### You might want a sub-subheading (h4)

In arcu magna, aliquet vel pretium et, molestie et arcu. Mauris lobortis nulla et felis ullamcorper bibendum. Phasellus et hendrerit mauris.

In arcu magna, aliquet vel pretium et, molestie et arcu. Mauris lobortis nulla et felis ullamcorper bibendum. Phasellus et hendrerit mauris.

#### But it's probably overkill (h4)

In arcu magna, aliquet vel pretium et, molestie et arcu. Mauris lobortis nulla et felis ullamcorper bibendum. Phasellus et hendrerit mauris.

##### Could be a smaller sub-heading, `pacman` (h5)

In arcu magna, aliquet vel pretium et, molestie et arcu. Mauris lobortis nulla et felis ullamcorper bibendum. Phasellus et hendrerit mauris.

###### Small yet significant sub-heading  (h6)

In arcu magna, aliquet vel pretium et, molestie et arcu. Mauris lobortis nulla et felis ullamcorper bibendum. Phasellus et hendrerit mauris.

### Highlight the code please!!

{% highlight c %}
#!/usr/bin/env python3

# tomsom
# Derived from Sarah Edwards' SANS FOR518

# Truffleshuffle is a simple script that parses the Mac OS
# ChunkStoreDatabase and ChunkStorage to carve versioned files.

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

### Oh hai, an unordered list!!

In arcu magna, aliquet vel pretium et, molestie et arcu. Mauris lobortis nulla et felis ullamcorper bibendum. Phasellus et hendrerit mauris.

- First item, yo
- Second item, dawg
- Third item, what what?!
- Fourth item, fo sheezy my neezy

### Oh hai, an ordered list!!

In arcu magna, aliquet vel pretium et, molestie et arcu. Mauris lobortis nulla et felis ullamcorper bibendum. Phasellus et hendrerit mauris.

1. First item, yo
2. Second item, dawg
3. Third item, what what?!
4. Fourth item, fo sheezy my neezy

## Headings are cool! (h2)

Proin eget nibh a massa vestibulum pretium. Suspendisse eu nisl a ante aliquet bibendum quis a nunc. Praesent varius interdum vehicula. Aenean risus libero, placerat at vestibulum eget, ultricies eu enim. Praesent nulla tortor, malesuada adipiscing adipiscing sollicitudin, adipiscing eget est.

Praesent nulla tortor, malesuada adipiscing adipiscing sollicitudin, adipiscing eget est.

Proin eget nibh a massa vestibulum pretium. Suspendisse eu nisl a ante aliquet bibendum quis a nunc.

### Tables

Title 1               | Title 2               | Title 3               | Title 4
--------------------- | --------------------- | --------------------- | ---------------------
lorem                 | lorem ipsum           | lorem ipsum dolor     | lorem ipsum dolor sit
lorem ipsum dolor sit | lorem ipsum dolor sit | lorem ipsum dolor sit | lorem ipsum dolor sit
lorem ipsum dolor sit | lorem ipsum dolor sit | lorem ipsum dolor sit | lorem ipsum dolor sit
lorem ipsum dolor sit | lorem ipsum dolor sit | lorem ipsum dolor sit | lorem ipsum dolor sit

Title 1 | Title 2 | Title 3 | Title 4
--- | --- | --- | ---
lorem | lorem ipsum | lorem ipsum dolor | lorem ipsum dolor sit
lorem ipsum dolor sit amet | lorem ipsum dolor sit amet consectetur | lorem ipsum dolor sit amet | lorem ipsum dolor sit
lorem ipsum dolor | lorem ipsum | lorem | lorem ipsum
lorem ipsum dolor | lorem ipsum dolor sit | lorem ipsum dolor sit amet | lorem ipsum dolor sit amet consectetur
