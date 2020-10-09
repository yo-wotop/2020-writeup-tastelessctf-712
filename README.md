# 7/12

This challenge was part of the 2020 Tasteless CTF. In the previous challenge (7/11), the player obtained a folder (`part2/`) containing 376 `7zip` files. These files are included in this repository (`challenge/`) for reproduction.

## Prior Knowledge

Going into this, you'd have some basic knowledge due to having solved 7/11. In particular, you'd at least understand the `7z` archive header, which points you to the location of the footer's starting address. See below:

![1](https://user-images.githubusercontent.com/72385703/95572027-374b3f00-09de-11eb-8ead-61a29f8aa05e.png)

Keep that in mind as we continue, as the knowledge of the footer's start address is required prior to attempting this. 

## Initial Observations

Within the 376 `7zip` archives were 1-5 `junk_#.bin` files. Typical players would likely begin by opening individual archives, extracting the contents, and trying to combine them into unified binaries.  

![2](https://user-images.githubusercontent.com/72385703/95572279-9315c800-09de-11eb-85e5-6bb5c590f5f5.png)

<sub><sub><sub>Spoiler: that leads nowhere.</sub></sub></sub>

After wasting some time on that rabbit hole, we can look inside of the `7z` files themselves. Opening the first file (`part2_0.7z`) in a hex editor, we noted the appearance of `PNG` and `IHDR` headers within the file. 

![3](https://user-images.githubusercontent.com/72385703/95572454-d4a67300-09de-11eb-81bb-87e68881a7fc.png)

The existence of a striped `PNG` could be confirmed by opening the final file (`part2_375.7z`) and observing the `IEND` tag.  

![4](https://user-images.githubusercontent.com/72385703/95572585-028bb780-09df-11eb-94f1-20fe66fc267b.png)

Easy peasy, right? The first file contained 0x11 `PNG` bytes. We'll simply loop through all 376 files, extract the 0x11 bytes just before the footer, and concatenate them into a final `PNG` file. Writing this script took about 3 minutes. And just like that, bingo, [solved.png](https://user-images.githubusercontent.com/72385703/95572640-1b946880-09df-11eb-868c-d180f731ebed.png)!  

## Take Two

With this set back, we figured that the amount of characters within each file must vary. We knew that the data ended where the footer began, which was clearly noted within the header properties. However, we needed to determine a way to know the length of the packed body data. Or the end of the packed body data. Or the length of the `PNG` data.

With more research into the `7z` specification, we eventually stumbled upon [7z_parser.py](https://github.com/yo-wotop/2020-writeup-tastelessctf-712/blob/main/solution/7z_parser.py). I have no idea who wrote this thing, as I can only find it on some random github repository with a bunch of other, unrelated tools. By running it against a variety of files, we noticed a pattern emerge:  

![6](https://user-images.githubusercontent.com/72385703/95573491-62cf2900-09e0-11eb-9cfc-84c84b006a9d.png)


Note how the `dataOffset`, `packSize[0]`, and `0x20` add up to the exact `0x200` confirmed start of the `PNG` header? This makes sense, as these are the values that indicate where packed data and offsets from compressed metadata are stored. Adding them together, we get the length of the body data. Combining that with 0x20 (the start of the body data), we obtain the ending address of the body data -- the starting address of the steganographic data!  

We verified that this was also true for `part2_1.7z`, `part2_2.7z`, and even `part2_375.7z`. Not as easy as we first thought, but no sweat. Took us about 40 minutes overall. Now, we had all the pieces necessary to extract the data and create... `solved2.png`!

![7](https://user-images.githubusercontent.com/72385703/95573680-af1a6900-09e0-11eb-9f62-1d4882122901.png)

<sub><sub><sub>And yet 7z supports file formats with a literal 7z file embedded into another 7z? You've gotta be kidding me.</sub></sub></sub>

## Third Try's The Charm

Nah, the third try wasn't the charm. Nor was the fourth try. Or the fifth. Or even the sixth. You see, there was a long-standing battle against how `7zip` treats "Numbers." Numbers in 7zip follow this cute little chart:  

|  First_Byte (binary)  |  Extra_Bytes  |  Value (y: little endian integer)  |
|----|----|----|
|0xxxxxxx|    |(0b0xxxxxxx)    |
|10xxxxxx|BYTE y[1]|(0b00xxxxxx << (8 * 1)) + y|
|110xxxxx|BYTE y[2]|(0b000xxxxx << (8 * 2)) + y|
|1110xxxx|BYTE y[3]|(0b0000xxxx << (8 * 3)) + y|
|11110xxx|BYTE y[4]|(0b00000xxx << (8 * 4)) + y|
|111110xx|BYTE y[5]|(0b000000xx << (8 * 5)) + y|
|1111110x|BYTE y[6]|(0b0000000x << (8 * 6)) + y|
|11111110|BYTE y[7]|y|
|11111111|BYTE y[8]|y|


So yeah. That's simple enough. And the `7z_parser.py` file? Well, it was coded in Python2. Our script was Python3. That presented no challenges. It was using bytestreams where we were using dictionaries, too. But at least the `7z_parser.py` was documented very well, with helpful gems like below:  

```
    ormask = (mask - 0x80)
    # print("ormask: %s" % hex(ormask))
    unpack_str = "B"  # lololol

    for i in range(1, inp_len):
```

<sub><sub><sub>I think I may have figured out who made `7z_parser.py`, considering it seems to have been piped up directly from hell.</sub></sub></sub>

The "lololol" had a special place in our hearts, as it mocked our inability to implement `read_number()` cleanly from `solved3.png` through `solved5.png`. So instead, we settled on a simpler solution:

```
import subprocess
import re

folder = '/shr/part2/'
solved = folder + 'solved8.png'

DO_REGEX = 'dataOffset\\s*:\\s*(0x[^\\s]*)'
PS_REGEX = 'packSize\\[\\d\\]\\s*:\\s*(0x[^\\s]*)'
errors = []
def getData(file_number):
    global errors
    # Run the fucking guy's shit lol
    fil = 'part2_%s.7z' % file_number
    p = subprocess.run(['python2','../7z_parser.py', fil], cwd=folder, stdout=subprocess.PIPE,
                                timeout=2, env={})

    text = p.stdout.decode()

    try:
        data_finds = re.findall(DO_REGEX, text)
        pack_finds = re.findall(PS_REGEX, text)

        data_offset = int(data_finds[0], 16)
        packed_size = int(pack_finds[0], 16)

        return data_offset, packed_size
...
```

You're reading that correctly. We were running the `7z_parser.py` script **as a subprocess** and then regex parsing through its `stdout`. This worked fantastically, and `solved7.png` (a very fitting name for the final file on a challenge about **7**zip) FINALLY got to shine!  

![solved7](https://user-images.githubusercontent.com/72385703/95574391-b8f09c00-09e1-11eb-85d7-cc7dbf5904c4.png)

<sub><sub><sub>Depending on what program you use to view it, you see different images!.. or segfault the Windows Photo viewer...</sub></sub></sub>

## Please Don't Make Us Go To 12

After doing some digging, we discovered the problem. We're idiots. Also, the `7z_parser.py` script simply doesn't work for LZMA2-encoded files that contain `File` information. Consider the following parse of `part2_5.7z`:  

![8](https://user-images.githubusercontent.com/72385703/95575383-792ab400-09e3-11eb-8101-a56a95f6977e.png)

No `data_offset`. No `packSize[0]`. Not even data about the file names, which are clearly visible in plaintext in the footer.  

Desperately thinking that we were going to need to end up with `solved12.png` before getting the flag, we innovated a brand-new solution. One unlike anything we ever tried before.

We COMBINED the wonky `read_number()` implementation that we half-janked together for `solved3-5.png` as a failsafe, with, and you'll never believe this, the `subprocess` implementation from `solved7.png`. And voila, `solved8.png`  

![9](https://user-images.githubusercontent.com/72385703/95575546-bbec8c00-09e3-11eb-834f-be15778d522d.png)  

## Did you parse the properties?

Our victory was shorter lived than my last relationship, unfortunately, as that question immediately slapped us in the face. **"No."** We didn't really parse the properties. We janked it together 8 ways from Sunday. You can find the exact script(s) used in this repository as well, under `solution/`. You shouldn't, though. Nothing good can come from that.  

So our solution was a little disheartening. For five distinct reasons:

1. We still didn't really know `7zip` all that well.
2. It was ugly. Really ugly. Not worth making a write-up about, except to mock it for being trash.
3. I was reminded about the failure of my last relationship as I wrote this write-up. 
4. It relied heavily on copy-pasta. Copy-pasta that even its creator didn't love.  
5. It brought to light the problem that no decent `7zip` parser existed in this world. And that the `7zip` documentation [is really, really trash](https://fastapi.metacpan.org/source/BJOERN/Compress-Deflate7-1.0/7zip/DOC/7zFormat.txt).

Naturally, we did the only logical next step that anyone in the same position would have done: **we created a new 7z parser from scratch.**

# 7z-tools

And so we set about to create [7z-tools](https://github.com/yo-wotop/7z-tools). These tools are based on similar concepts to the `7z_parser.py` script, except written in Python3 and intended for future use and extensibility. They're built around a core `Zip7` class, which parses many key data properties upon instantiation. There are no "fuck lololol" comments, and it isn't even broken! Note how the `data_offset` and `pack_size` values appear for `sample_5.7z`  

```
$ ./parse7z.py part2_5.7z
=====================================
--------- Header Properties ---------
Magic - - - - - - - - 7z\xbc\xaf'\x1c
Version - - - - - - - 4
Header CRC- - - - - - 0x70c6c868
Header CRC Valid? - - True
Footer Start- - - - - 0xa1
Footer Length - - - - 0x62
Footer CRC- - - - - - 0x72f2a1a1
Footer CRC Valid? - - True
=====================================
--------- Footer Properties ---------
Data Offset - - - - - 0x0
Pack Size(s)- - - - - [0x63]
Compression - - - - - LZMA2
=====================================
---------- Body Properties ----------
Body Length - - - - - 0x63
=====================================
---------- Steg Properties ----------
Center Start- - - - - 0x83
Center Length - - - - 0x1e
Center Data - - - - - b',\xcc\xf8C\x92-\xd9\xfc\x7f\xe7\xe8y\xd8\xdd`[\x9a\xd1\xcch\xac\x8f\xc9YA\x00\x00\x00\x00\x00'
Bottom Start- - - - - 0x103
Bottom Length - - - - 0x0
Bottom Data - - - - - b''
=====================================
```

<sub><sub><sub>Yep. That's the stego data right there, in `file.steg.center_data`.</sub></sub></sub>

## Yes

And since we had an actual internal parsing library, we could make a variety of scripts. The scripts [are heavily documented in the repository](https://github.com/yo-wotop/7z-tools/blob/main/README.md), so they won't be repeated here. However, let's just say that they allow us to solve this challenge in a single line:

```
$ ./7zsteg.py challenge/part2_*.7z >> ez.png
```

And just like that, `tstlss{Nice!_Did_you_parse_the_properties?}` is a single line away. And it's official.

**Yes.** We parsed the properties.

