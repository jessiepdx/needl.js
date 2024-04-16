# needl.js
**NEEDL** -- securely store and retrieve data within a photograph; _like finding a **needl**e in a haystack._

> demo:  https://needl-ui-demo.netlify.app/

## About
Needl uses four pieces of unique data to securely store and retrieve data in photographs. We all have hundreds, if not thousands of photographs on our personal devices such as our phones, tablets, and computers; not to mention also stored on various websites on the internet. Most of these photographs have tens of millions of pixels. Pixels represent the colors of light spectrum in values of *red, green, and blue* producing a 24bit value (nearly seventeen million) of color possibilities.  
Let's think of a photograph as a unique two dimensional map of pixels then -- each map with millions of locations and millions of possibile values at each location. Needl navigates this unique map using coordinates it creates from three unique keys:  **passkey1**, **passkey2**, and the photo's **filename**. These keys are turned into cyrptographic hashes using techniques similar to how websites handle password storage and verification.

Therefore Needl takes in the following four pieces of unique data and returns your data hidden within.
* Photograph - as a unique map of pixel data, with your data hidden within
* Filename - the filename of the photo is used (along with other modifiers) to create a hashing salt as well as other **_modifier_** values
* Passkey1 - is hashed along with it's own salt and returns a 64 character length hash. This value becomes part of the algorithm for **_x axis_** coordinates
* Passkey2 - is hashed along with it's own salt and returns a 64 character length hash. This value becomes part of the algorithm for **_y axis_** coordinates

It is only by using the same four unique pieces of data can you retrieve the hidden data you seek.

## Use Cases
### **Using Needl as a passkey generator / manager**
Using the coordinates our algorithm generates from your passkey hashes, it _decodes_ the "raw" data in your unique map of pixels (photograph) and returns a 32-256 character string containing letters from `[A-Z]` `[a-z]` as well as numeric digits `[0-9]` and also any of the following symbols:  ``[ !"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~]``. You also have the ability to set the minimum number of capital letters and digits as well as setting which symbols are allowed making it simple to fulfill the password requirements of nearly any website. _See **options** in the **documentation** below for more details._  

This _**passkey signature** (aka **needl**)_ can then be used as a very **strong** passkey. Anytime you need to access this _**passkey signature**_ again in the future, just decode it using the same unique photograph _(aka **haystack**)_ with the correct filename and unique passkeys. You can also use the same photograph and change just one key and get a completely different _**passkey signature**_ -- meaning you can use a **single** photo for all of your passkeys.

This can be used as a _stand-alone application for **personal** use_ **or** _incorporated into your own **web and app** projects_ to give your users the ability to use a simple, easy to remember passkey _(word or phrase)_ but still use the very **strong** passkeys generated by Needl to secure their accounts on the server side.

#### Using as a stand-alone webapp
The functionality of Needl is meant to run 100% serverless. With one of our UI examples, you can use Needl by itself on your own devices -- even without an internet connection.

##### Stand-alone examples
**_Example 1 (stand-alone):_**
![A photograph of haybales](https://github.com/jessiepdx/needl.js/blob/main/examples/Haystack-1433186.jpg) 
[Image by Studiolarsen](https://pixabay.com/users/studiolarsen-2686243/?utm_source=link-attribution&utm_medium=referral&utm_campaign=image&utm_content=1433186) [from Pixabay](https://pixabay.com//?utm_source=link-attribution&utm_medium=referral&utm_campaign=image&utm_content=1433186)  
> This photo is used for all examples and can be found in the examples folder  
1. Photograph (4200 x 3000 - total of 12,600,000 pixels)
2. Filename:  "Haystack-1433186.jpg"
3. passkey1:  "MyEasyPassword"  
4. passkey2:  "personal instagram"  
_*notice that you can use both pass**words** and pass**phrases** for your passkeys_

Using this unique map of pixels, and three unique keys:  **filename**, **passkey1**, and **passkey2** returns the following _passkey signature_
>?pTP1I}(#IX3'%q!\[{e1A6(,=\[INKO1Gvv\[bR2xq=.or.Bo-pZ]B$xm*l3TkFAeLsm%C!CCk^vpc3/FM|+4wGwt>?aPb$\\]M:Izu.Io7WL::hsIIUS2i0Cn3&VeD]S2Z  
_(default needl size of 128)_

Changing just one piece of data in either **filename**, **passkey1**, or **passkey2** will result in a completely different _passkey signature_.

**_Example 2 (stand-alone):_**
1. Photograph (4200 x 3000 - total of 12,600,000 pixels)
2. Filename:  "Haystack-1433186"
3. passkey1:  "MyEasyPassword"  
4. passkey2:  _"work email"_

Will return the following _passkey signature_:
>CcvTeBO_=ay5@6S+>cJS)ONH,D[6(,=[#!_-#u|!aOIlQI}((Ies\~1DSFu\pUaN\\+Cx?/6na>vadaU6na@_J/\~_f=4\\$Wz.(az[@WVxp$c^'{~fszH6wP"[R\6Ti[6nq

#### Used in website or application
The same principals of the stand alone application apply to using within your websites / apps. As the developer, you can choose to provide one of the unique keys or _modifiers_ and therefore only require your users to provide the correct photo with a **single passkey**. This can be used for standard sign-in practices or as a 2FA method to prove identity.

##### Website login examples

**_Example 1 (website sign-in):_**
1. Photograph (4200 x 3000 - total of 12,600,000 pixels)
2. Filename:  "Haystack-1433186"
3. passkey1:  "MyEasyPassword"  
4. passkey2:  "1acf9d4fd9140b5ee70d86571f9da62b31a795453f439992d14aee4d05b71f45"  
_passkey2 is filled out with the website's public key (we used github's for this example)_

Will return the following _passkey signature_:
>oY-8[)po%XGF{"[)m;!S^XxU?jUe)&c_To\~pd&JoIK>J6nt<;%]bApd\~1\RcI.WKIzCi6)\M8$WN/]XfoXkIo:Fq[7q=G)<H;H!9d(_H4IXdw%m/+\1t!I}i?x"SE\\)a

In this example, the user is only asked for their photo and a single passkey. The resulting Needl is sent back to the server and handled like any other password (salted by the server and compare the result with the hash stored in a database)

**_Example 2 (website sign-in):_**
1. Photograph (4200 x 3000 - total of 12,600,000 pixels)
2. Filename:  "Haystack-1433186"
3. passkey1:  "Username as passkey1"  
4. passkey2:  "Password as passkey2"  
_Using the following options `{"ndlSize" : 32, "ndlCount" : 2}` we will recieve back two unique passkey signatures_

Will return the following _passkey signatures_:
>Sx)}R|tTo4J$Bo-pZPA4BI2[6GFh;5Y^

>x<b*}s\YcJM(6nqsp6na;XdnZJ@pzsBz

In this example, the first unique key is sent to the server as the username and the second as the password. This allows for anonymous usernames, protecting the users identity by not using an email address as a username.

### **Storing custom data within a photograph**
This was Needl's main function when it was first created in 2018 -- mainly intended for hiding private keys for cyrptocurrencies. For now this feature has been left out, but it will be added back again. Many changes were made to the encoding / decoding algorithms used since the original project.  
Compressed image types, like jpeg, do not store their RGB data for each individual pixel. When unpacking compressed images back into indivual pizels, RGB values may not be calculated the same as they were in the original image. Therefore, it cannot be gauranteed that data encoded in lossy formats will remain.

### Additional modifiers
The **ndlDate** modifier adds additional uniqueness to the salting process. This can be useful for passwords that are required to be changed with time based frequency.

## Documentation

### Construction ###
Create and store in a variable a new instance of Needl class. The constructor takes an HTML image `<img>`, filename `String`, passkey1 `String`, and passkey2 `String` — as well as optional _options_ stored as a collection of key-value pairs `{}`. *See below for options examples.*  
**New instance construction example:**  `let ndl = new Needl(img, fn, pk1, pk2);`

Needl uses JavaScript's SubtleDigest to create the hashes it uses. This is an asynchronous function that returns a `Promise`. JavaScript class constructors cannot return a `Promise`, therefore it's best to handle generating these hashes the first time the secret _passkey signature (aka **needl**)_ value is requested by calling it's getter method `ndl.needl`. This returns a `Promise` that resolves to the _passkey signature_ `String`.

### Options ###
Without passing an options value in the constructor, the constant `needl_defaults` values will be used. To set custom options, add key-value pairs to a simple object `{}` from the following available options:  
* **ndlCount** - Set the number of Needl _passkey signatures_ to return. Default value is 1.
* **ndlSize** - Set to a value of 0 to decode previously encoded images until a `Null` byte value (0) is found. To generate a unique _passkey signature_, set to a value from 32 to 256
* **minCapitals** - Set to a value between 1-4 to require a minimum amount of capital letters `[A-Z]` required in your _passkey signature_  
* **minDigits** - Set to a value between 1-4 to require a minimum amount of digits `[0-9]` required in your _passkey signature_
* **minSymbols** - Set to a value between 1-4 to require a minimum amount of symbols ``[ !"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~]`` required in your _passkey signature_
* **allowedSymbols** - A `String` of allowed symbols from the set ``[ !"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~]``
* **splitByte** - Splits the value of decoded Bytes. Values of 128-255 are reduced by 128 to increase useable values.
* **ndlDate** - A Numerical representation of a `Date` such as the `DD-MM-YYYY` format from html `<input type="date">`. This value acts as a modifier to the start x, y position as well as modifying the salting string

### Public Methods ###

**filename** (Getter) - example:  `ndl.filename` returns a string with the image filename (sans file extension) that was used in the hash salting process.  

**haystack** (Getter) - example:  `ndl.haystack` returns the image in a lossless `PNG` format.  

**needl** (Getter) - example:  `ndl.needl` returns the _passkey signature_ generated. The first time this is called, it returns a `Promise`. It must generate the hashes, which requires asyncronous methods, and then iterates pixels and decodes your image.  

**results** (Getter) - example: `ndl.results` returns a simple object `{}` containing the following properties:
* _iterations_ - the number of total iterations made
* _totalPixels_ - the total number of pixels within the image
* _valid_ - the total number of valid color channels found (a Delta of 5 or less from source pixel's channel value)
* _invalid_ - the total number of invalid channels found (and hence skipped over)

## Additional Information
**CREATED:**  2018  
**UPDATED:**  04/15/2024  
**VERSION:**  1.0.0b  
**NEW:**  
**FIXES:**  
**TODO:**
* Improved validation of input arguements
* Add encoding method (in version 2)
