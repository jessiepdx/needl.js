# needl.js
**NEEDL** -- securely store and retrieve data within a photograph; _like finding a **needl**e in a haystack._

## About
Needl uses four pieces of unique data to securely store and retrieve data in photographs. We all have hundreds, if not thousands of photographs on our personal devices such as our phones, tablets, and computers; not to mention also stored on various websites on the internet. Most of these photographs have tens of millions of pixels. Pixels represent the colors of light spectrum in values of *red, green, and blue* producing a 24bit value (nearly seventeen million) of color possibilities.  
Let's think of a photograph as a unique two dimensional map of pixels then -- each map with millions of locations and millions of possibile values at each location. Needl navigates this unique map using coordinates it creates from three unique keys:  **passkey1**, **passkey2**, and the photo's **filename**. These keys are turned into cyrptographic hashes using techniques similar to how websites handle password storage and verification.

Therefore Needl takes in the following four pieces of unique data and returns your data hidden within.
* Photograph - as a unique map of pixel data, with your data hidden within
* Filename - the filename of the photo is used (along with other modifiers) to create a hashing salt as well as other **_modifier_** values
* Passkey1 - is hashed along with it's own salt and returns a 64-1024 length hash. This value becomes part of the algorithm for **_x axis_** coordinates
* Passkey2 - is hashed along with it's own salt and returns a 64-1024 length hash. This value becomes part of the algorithm for **_y axis_** coordinates

It is only by using the same four unique pieces of data can you retrieve the hidden data you seek.

## Use Cases
### **Using Needl as a passkey generator / manager**
Using the coordinates our algorithm generates from your passkey hashes, it _decodes_ the "raw" data in your unique map of pixels (photograph) and returns a 32-256 character string containing letters from `[A-Z]` `[a-z]` as well as numeric digits `[0-9]` and also any of the following symbols:  `[symbols here]`. You also have the ability to set the minimum number of capital letters and digits as well as setting which symbols are allowed making it simple to fulfill the password requirements of nearly any website. _See **options** in the **documentation** below for more details._  
This _**passkey signature** (aka the **needl**)_ can then be used as a very **strong** passkey. Anytime you need to access this _**passkey signature**_ again in the future, just decode it using the same unique photograph _(aka the **haystack**)_ (with the correct filename) and unique passkeys. You can also use the same photograph and change just one key and get a completely different _**passkey signature**_ -- meaning you can store all of your passkeys in a **singl**e photo.

This can be used as a _stand-alone application for **personal** use_ or _incorporated into your own **web and app** projects_ to give your users the ability to use a simple, easy to remember passkey _(word or phrase)_ but still use the very **strong** passkeys generated by Needl to secure their accounts on the server side.

#### Using as a stand-alone webapp
The functionality of Needl is meant to run 100% serverless. With one of our UI examples, you can use Needl by itself on your devices -- even without an internet connection.

##### Stand-alone examples
**_Example 1 (stand-alone):_**
![A photograph of haybales](https://github.com/jessiepdx/needl.js/blob/main/examples/Haystack-1433186.jpg) 
[Image by Studiolarsen](https://pixabay.com/users/studiolarsen-2686243/?utm_source=link-attribution&utm_medium=referral&utm_campaign=image&utm_content=1433186) [from Pixabay](https://pixabay.com//?utm_source=link-attribution&utm_medium=referral&utm_campaign=image&utm_content=1433186)  
1. Example photograph (4200 x 3000 - total of 12,600,000 pixels)
2. Filename:  "Haystack-1433186.jpg"
3. passkey1:  "MyEasyPassword"  
4. passkey2:  "personal instagram"  
_*notice that you can use both pass**words** and pass**phrases** for your passkeys_

Using this unique map of pixels, and three unique keys:  filename, passkey1, and passkey2 returns the following _passkey signature_
>h$NWdOII4&FyF7\H6N7b\`J_9R)MvY-N~wjAxG#uj\XM+@zQI\`iH3H-zI\`4-gSqdgg,+|Or\7ztqGmLcanuGFz0j4Irmco(Tu:1XH)L&}fpBm}OC8M/Pav'Z9]I}I}jls  
_(default needl size of 128)_

Changing just one piece of data in either filename, passkey1, or passkey2 will result in a completely different _passkey signature_.

**_Example 2 (stand-alone):_**
1. Example photograph (4200 x 3000 - total of 12,600,000 pixels)
2. Filename:  "Haystack-1433186.jpg"
3. passkey1:  "MyEasyPassword"  
4. passkey2:  "work email"

Will return the following _passkey signature_:
>Wkk?gJ}=t9K>&nzzYYM}QI6V5~R-P.M)Irj7]3Mn72OZdIp;^B5QIoWI{(BQS7FaG:y\e5fTV#XRJCLymON#jR%cvU's\3]sg'Ap;X>IoWXZjIo|#gb&R'-KrH}[iH$7

#### Used in website or application
The same principals of the stand alone application apply to using within your websites / apps. As the developer, you can choose to provide one of the unique keys or modifiers and therefore only require your users to provide the correct photo with a **single passkey**. This can be used for standard sign-in practices or as a 2FA method to prove identity.

##### Website login examples

**_Example 1 (website sign-in):_**
1. Example photograph (4200 x 3000 - total of 12,600,000 pixels)
2. Filename:  "Haystack-1433186.jpg"
3. passkey1:  "MyEasyPassword"  
4. passkey2:  "1acf9d4fd9140b5ee70d86571f9da62b31a795453f439992d14aee4d05b71f45"  
_passkey2 is filled out with the website's public key (we used github's for this example)_

Will return the following _passkey signature_:
>^xHI}W{s8gO=ZF&CRBqbtDfLc}90aTg"$f=63{ghu@~)f*\<~;.0:"K6MU(*XiIeLE\`jBBzt\}BP|I=AHLgni7T"9Wr[yDt@8}Cql:$phpliPebfO;pogDO)w!RfIza;

### **Storing custom data within a photograph**
This was Needl's main function when it was first created in 2018 -- mainly intended for hiding private keys for cyrptocurrencies. For now this feature has been left out, but it will be added back again. Many changes were made to the encoding / decoding algorithms used since the original project. Currently, one of the only downsides to encoding custom data into a photograph is having to save that photo as a lossless format such as PNG or BMP. This is because compressing photos changes their pixel's RGB values just enough that values encoded into the pixels are lost.

### Additional modifiers

## Documentation

Create and store in a variable a new instance of Needl class. The constructor takes an image `<img>`, filename (string), passkey1 (string), and passkey2 (string) — as well as optional _options_ stored as a collection of key-value pairs. *See below for options examples.*  
**New instance construction example:**  `let ndl = new Needl(img, fn, pk1, pk2);`

Needl uses JavaScript's SubtleDigest to create the hashes it uses. This is an asynchronous function that returns a `Promise`. JavaScript class constructors cannot return a `Promise`, therefore it's best to handle generating these hashes the first time the secret _passkey signature (aka **needl**)_ value is requested by calling it's getter method `ndl.needl`. This returns a `Promise` that resolves to the _passkey signature_ `String`.

## Additional Information
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
