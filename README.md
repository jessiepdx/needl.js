# needl.js
**NEEDL** -- securely store[^1] and retrieve data within a photograph; _like finding a **needl**e in a haystack._

## About
Needl uses four pieces of unique data to securely store[^1] and retrieve data in photographs. We all have hundreds, if not thousands of photographs on our personal devices such as out phones, tablets, and computers; not to mention also stored on various websites on the internet. Most of these photographs have tens of millions of pixels. Pixels represent the colors of light spectrum in values of *red, green, and blue* producing nearly seventeen million color possibilities.  
Let's think of a photograph as a unique two dimensional map of pixels then -- each map with millions of locations and millions of possibile values at each location. Needl navigates this unique map using coordinates it creates from three unique keys:  **passkey1**, **passkey2**, and **filename**. These keys are turned into cyrptographic hashes[^2] using techniques similar to how websites handle password storage and verification.

Therefore Needl takes in four pieces of unique data and returns your data hidden within.
* Photograph - as a unique map of pixel data, with your data hidden within
* Filename - the filename of the photograph is used to create a hashing salt[^3] (along with other modifiers) as well as a **_modifier_** value
* Passkey1 - is hashed along with it's own salt and returns a 256-1024 length hash. This value becomes part of the algorithm for **_x axis_** coordinates
* Passkey2 - is hashed along with it's own salt and returns a 256-1024 length hash. This value becomes part of the algorithm for **_y axis_** coordinates

Only by using the same four unique pieces of data can you retrieve the hidden data you seek.

## Use cases
**Using Needl as a passkey generator / manager** - using the coordinates our algorithm generates from hashes, it _decodes_ the raw data in your unique map of pixels (photograph) and returns a 128-512 character string containing letters from `[A-Z]` and `[a-z]` as well as numeric digits `[0-9]` and also any of the following symbols:  `[symbols here]`  
This _passkey signature_ we refer to as a _needl_ can then be used as a very **strong** password. Anytime you need to access that _passkey signature_ again in the future, just decode it using the same unique photograph (with the correct filename) and unique passkeys. You can use the same photograph and change just one key and get a completely different _passkey signature_.

This can be used as a stand-alone application for personal use or incorporated into your own web and app projects to give your users the ability to use a simple, easy to remember passkey (word or phrase) but use very strong passkeys generated by Needl to secure their accounts.

**_Example 1:_**
![alt text](https://pixabay.com/get/g5b964b8488ea5a3855d636fec6aefb131b8c51b2007c6abc327cf56b62a355005b8d5ae6dc7e7b249f9837b86e71735b.jpg)
[Image by Studiolarsen](https://pixabay.com/users/studiolarsen-2686243/?utm_source=link-attribution&utm_medium=referral&utm_campaign=image&utm_content=1433186) [from Pixabay](https://pixabay.com//?utm_source=link-attribution&utm_medium=referral&utm_campaign=image&utm_content=1433186)  
1. Example photograph (4200 x 3000 - total of 12,600,000 pixels)
2. Filename:  "Haystack-1433186.jpg"
3. passkey1:  "MyEasyPassword"  
4. passkey2:  "personal instagram"

Using this unique map of pixels, and three unique keys:  filename, passkey1, and passkey2 yields the following _passkey signature_
>h$NWdOII4&FyF7\H6N7b`J_9R)MvY-N~wjAxG#uj\XM+@zQI`iH3H-zI`4-gSqdgg,+|Or\7ztqGmLcanuGFz0j4Irmco(Tu:1XH)L&}fpBm}OC8M/Pav'Z9]I}I}jls

**Storing custom data within a photograph** - this was Needl's main function when it was first created in 2018 -- mainly intended for hiding private keys for cyrptocurrencies. For now this feature is left out, but it will be added back again. Many changes were made to the encoding / decoding algorithms used. Currently, one of the only downsides to encoding custom data into a photograph is having to store that photo as a lossless format such as PNG or BMP. This is because compressing photos changes their pixels RGB values just enough that values encoded into the pixels are lost.

## Documentation

Create and store in a variable a new instance of Needl class. 
The constructor takes an image `<img>`, filename (string), passkey1 (string), 
and passkey2 (string) — as well as optional _options_ stored as a collection
 of key-value pairs. *See below for options examples.*  
**New instance construction example:**  `let ndl = new Needl(img, fn, pk1, pk2);`

Needl uses JavaScript's SubtleDigest to create the hashes it uses. 
This is an asynchronous function that returns a `Promise`. 
JavaScript class constructors cannot return a `Promise`, 
therefore it's best to handle generating these hashes the first time the 
secret passkey signature (nicknamed *"needl"*) value is requested by calling it's 
getter method `ndl.needl`. This returns a `Promise` that resolves to the 
passkey signature (string).

**CREATED:**  2018
**UPDATED:**  03/27/2024
**VERSION:**  0.1.1b
**NEW:**
**FIXES:**
**TODO:**  Validation of input arguements (image size min requirements, passkey min requirements, filename min requirements) 
check for options argument object and set options accordingly (including datetime for salting) 
add encoding methods

[^1] functionality for storing data in lossless photo formats like PNG and BMP will be added back in ver 2.0
[^2] a string containing 256 - 1024 hexidecimal values
[^3] a unique value concatenated onto passkeys before hashing - for added security
