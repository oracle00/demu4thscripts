## Track Data Processor
Coded by Japanese
`gui_track_processor.py` is a GUI-based utility for converting raw card data and
track-formatted data used in arcade systems (such as Virtua On Force) into
different binary representations.  
It supports drag-and-drop input, automatic format detection, bit-order
conversion, and track reconstruction.

### Features

- **Automatic input detection**
  - HEX text input
  - Raw binary input
  - Existing track-formatted data (`0xFF + 69 bytes + 0xFF + BCC_NOT`)

- **Track processing**
  - Convert 69‑byte raw data blocks into track format  
    (`0xFF` header + body + `0xFF` + inverted BCC)
  - Restore raw card data from track-formatted input
  - Split raw data into multiple tracks

- **Bit-order reversal**
  - Each byte is reversed bit‑by‑bit before track generation or after track restoration

- **GUI interface**
  - Drag & drop a file to process it
  - Displays both input and output in HEX format
  - Dark‑theme UI using Tkinter + TkinterDnD2
  - Save input/output text to external files
