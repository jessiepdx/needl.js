# needl.js

**NEEDL:**  A simple multikey password generator / manager - all from a photo

**CREATED:**  2018

**UPDATED:**  03/27/2024

**VERSION:**  0.1.1b

**ABOUT:**  Using two simple passkeys and the photo filename to generate a hashing salt, Needl creates three unique hashes. One for the x axis, one for the y axis, and one as a modififer. 
Think of a photo as a large two dimensional map of pixels. Needl navigates through that map using coordinates that only your unique hashes can generate. 
Using the pixels at those unique coordinates, Needl calculates its own unique passkey signature. 
Now anytime you need to retrieve that passkey, you just need that photo, and your two passkeys.  
**_Example:_**  
1. Photo00179.jpg (this string itself is a part of salt string)  
2. passkey1:  "First hike with puppy"  (each of these passkeys are salted as well)  
3. passkey2:  "personal instagram"

Only this unique map of pixels, and three unique keys:  passkey1, passkey2, and filename (with datetime options for additional unique salting) 
will retrieve that same unique passkey signature. Use the same combination but a different string for passkey2, for example - "work instagram", 
you will get a completely different and unique passkey signature. 
Like finding a needle in a haystack.

    For more information, visit:  https://github.com/jessiepdx/needl.js

**NOTES:**  Considering making all methods private and a single public async method that returns the needl string in a promise

**TODO:**  Validation of input arguements (image size min requirements, passkey min requirements, filename min requirements) 
check for options argument object and set options accordingly (including datetime for salting) 
add encoding methods
