# Cover Images Directory

This directory contains images that are used as cover images in the steganography encryption process.

## Usage
- The system will automatically select a random cover image from this directory when encrypting Medical images
- No user selection of cover images is required
- The encryption process will embed the sensitive Medical image within the selected cover image

## Requirements
- Images should be in common formats: PNG, JPG, JPEG, GIF, BMP, TIFF
- Larger images work better for steganography (recommended minimum size: 800x600 pixels)
- Add a variety of images to make the encryption less predictable

## Adding Images
Simply add your cover images to this directory. The system will automatically include them in the rotation.

## Security Note
While the cover images themselves are not sensitive, it's recommended to use images that are not easily recognizable or traceable to maintain the security of the steganography process.
