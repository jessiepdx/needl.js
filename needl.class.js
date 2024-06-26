/*
Copyright (C) 2024  Jessie Wise

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.

NEEDL:  A simple multikey password generator / manager - all from a photo
CREATED:  2018
UPDATED:  04/04/2024
VERSION:  1.0.0b
ABOUT:
    Using two simple passkeys (or phrases) and the photo filename (also used to generate a hashing salt), Needl creates three unique hashes. One for the x axis, one for the y axis, and one as a modififer. 
    Think of a photo as a large two dimensional map of pixels. Needl navigates through that map using coordinates that only your unique hashes can generate.
    Using the pixels at those unique coordinates, Needl's algorithm extracts its own unique passkey signature. Now anytime you need to retrieve that passkey signature, you just need that photo and your two passkeys.
    Example:
        Photo00179.jpg (this name itself is a part of the salt string)
        passkey1:  "First hike with puppy"  (each of these passkeys are modified with their own salt string before hashing)
        passkey2:  "personal instagram"
    Only this unique map of pixels, and three unique keys:  passkey1, passkey2, and filename (with datetime options for additional unique salting) will retrieve that same unique passkey signature. 
    Use the same combination but a different string for passkey2, for example - "work instagram", you will get a completely different and unique passkey signature.
    Like finding a needle in a haystack.

    For more information, visit:  https://github.com/jessiepdx/needl.js
NOTES:
    It is advised not to rely on compressed image formats like jpeg. You can not gaurantee that they will be unpacked with the original RGB values. 
    Calling the getter method for haystack will return a lossless format (default PNG) of your original image, maintaining the correct RGB values per pixel.
TODO:
    Improved validation of input arguements
    Add encoding method (in version 2)
*/

// Default symbol sets
const symbol_sets = {
    "full" : " !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~", // according to https://owasp.org/www-community/password-special-characters
    "full_nospace" : "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~",
    "punctuation" : "?!.,;-'"
};

// Defaults set here overwrite the Needl class defaults.
const needl_defaults = {
    "ndlCount" : 1,
    "ndlSize" : 128,
    "minCapitals" : 1,
    "minDigits" : 1,
    "minSymbols" : 1,
    "allowedSymbols" : symbol_sets.full_nospace,
    "splitByte" : true
};

class Needl {
    // Keys and Salt
    #passkey1;
    #passkey2;
    #filename = "";
    //  NOTE:  dateSalt is added to cursor.modifier

    // Haystack and Needl
    #canvas = document.createElement("canvas");
    #haystack = this.#canvas.getContext("2d", { willReadFrequently: true, colorSpace: "srgb" });
    #cursor = { "start" : {}, "currentPos" : {}, "iterator" : {}, "modifier" : {} };
    #needl = [];

    // Buffers to hold values
    #base11Buffer = [];
    #byteBuffer = [];

    // Results data
    #totalValid = 0;
    #totalNotValid = 0;

    // Options
    #ndlOptions = {
        "ndlCount" : 1,
        "ndlSize" : 128,
        "minCapitals" : 1,
        "minDigits" : 1,
        "minSymbols" : 1,
        "allowedSymbols" : " !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~",
        "splitByte" : true
    };

    // Arguments:  image is an HTML image element; filename, pk1, and pk2 are strings; options is a key-value pair collection (not required)
    constructor(image, fn, pk1, pk2, options = {}) {
        // Merge options with needl_defaults and overwrite with assigned values
        this.#ndlOptions = {...this.#ndlOptions, ...needl_defaults, ...options};
        // Add the date modifier if set in options
        if (options.hasOwnProperty("ndlDate")) {
            this.#cursor.modifier.dateSalt = options.ndlDate;
        }
        
        // Validate data
        // Basic regular expression check
        let pk_regExp = /^[A-Za-z\d]+[A-Za-z\d. _-]{7,64}$/;
        let fn_regExp = /^[A-Za-z\d]+[A-Za-z\d. _-]{7,64}$/;
        
        // Check for required arguments
        if (!image || !pk1 || !pk2) {
            return { "invalid" : true, "errMsg" : "missing required arguments" };
        }
        // Check for valid arguements
        if (!pk_regExp.test(pk1) || !pk_regExp.test(pk2)) {
            return { "invalid" : true, "errMsg" : "passkeys requirements not met" };
        }

        // Check for valid filename
        if (!fn_regExp.test(fn)) {
            return { "invalid" : true, "errMsg" : "filename requirements not met" };
        }

        // Check for valid mime type
        //  TODO:  Create list of mimetypes compatible with HTML canvas
        const dataUrl = image.src;
        const mimetype = dataUrl.substring(dataUrl.indexOf(":")+1, dataUrl.indexOf(";"));

        // Check for minimum pixel count
        //  TODO:  will improve this later
        if (image.width * image.height < this.#ndlOptions.ndlSize * 1000 * 9) {
            return { "invalid" : true, "errMsg" : "not enough pixels in this image" };
        }
        
        // Everything is valid - draw image in canvas and set properties
        this.#haystack.canvas.width = image.width;
        this.#haystack.canvas.height = image.height;
        //  BUG:  iOS "jpg" from HEIC may not being drawing the image to the context.
        this.#haystack.drawImage(image, 0, 0);
        this.#filename = fn.replace(/\.[^/.]+$/, "");
        this.#passkey1 = pk1;
        this.#passkey2 = pk2;
    }

    // Using javascript's SubleCrypto functions are asyncronous and cannot be called within the constructor
    // Therefore a method to create the hashes is called separately
    async #makeHashes() {
        // First create a salt from filename
        let saltAlpha = this.#filename.match(/[A-Za-z]/g);
        let saltDigits = this.#filename.match(/\d/g);
        // Extract all digits from dateSalt if it exist, otherwise saltDate is an empty array
        let saltDate = (this.#cursor.modifier.hasOwnProperty("dateSalt")) ? this.#cursor.modifier.dateSalt.match(/\d/g) : [];
        // Multiplier is the sum of each individual digit from saltDigits and saltDate
        this.#cursor.modifier.multiplier = saltDigits.reduce((sum, val) => sum + parseInt(val, 10), 0) + saltDate.reduce((sum, val) => sum + parseInt(val, 10), 0);
        let saltString = saltAlpha.reduce((sum, val) => sum + val, "") + saltDigits.reduce((sum, val) => sum + val, "") + saltDate.reduce((sum, val) => sum + val, "");

        // Create two unique salt strings, one for each passkey
        let [pk1Salt, pk2Salt] = [...saltString].reduce((result, char, i) => (result[i%2].push(char), result), [[],[]]);
        let pk1SaltStr = pk1Salt.join("");
        let pk2SaltStr = pk2Salt.join("");

        // Hash the salt string
        const salt_charArray = new TextEncoder().encode(saltString);
        const salt_hashBuffer = await crypto.subtle.digest("SHA-256", salt_charArray);
        const salt_hashArray = Array.from(new Uint8Array(salt_hashBuffer));

        // Convert hash array data into 64 character string of hexidecimals
        this.#cursor.iterator.salt = salt_hashArray.map(b => b.toString(16).padStart(2, '0')).join('');

        // Hash both passkeys
        // X axis (passkey1)
        const pk1_charArray = new TextEncoder().encode(pk1SaltStr + this.#passkey1);
        const pk1_hashBuffer = await crypto.subtle.digest("SHA-256", pk1_charArray);
        const pk1_hashArray = Array.from(new Uint8Array(pk1_hashBuffer));

        // Set the x axis start point and iterator hash value
        this.#cursor.start.x = pk1_hashArray.reduce((sum, val) => sum + val, 0) % this.#canvas.width;
        this.#cursor.iterator.x = pk1_hashArray.map(b => b.toString(16).padStart(2, '0')).join('');

        // Y axis (passkey2)
        const pk2_charArray = new TextEncoder().encode(pk2SaltStr + this.#passkey2);
        const pk2_hashBuffer = await crypto.subtle.digest("SHA-256", pk2_charArray);
        const pk2_hashArray = Array.from(new Uint8Array(pk2_hashBuffer));

        // Set the y axis start point and iterator hash value
        this.#cursor.start.y = pk2_hashArray.reduce((sum, val) => sum + val, 0) % this.#canvas.height;
        this.#cursor.iterator.y = pk2_hashArray.map(b => b.toString(16).padStart(2, '0')).join('');

        if (salt_hashBuffer && pk1_hashBuffer && pk2_hashArray) {
            return true
        }
        else {
            return false;
        } 
    }

    #decode() {
        // Set current cursor position to the start x and y
        this.#cursor.currentPos = { 
            "x" : (this.#cursor.start.x * this.#cursor.modifier.multiplier) % this.#canvas.width, 
            "y" : (this.#cursor.start.y * this.#cursor.modifier.multiplier) % this.#canvas.height };
        
            // reset iterator counter
        this.#cursor.iterator.count = 0;
        
        // Decode until Null found in byteBuffer (previously encoded data)
        if (this.#ndlOptions.ndlCount == 0) {
            // This means iteratePixels until a byte value of 0 (Null) is decoded
            // Decoding previously encoded data terminated with a byte value of 0 (Null)
            return true; // when found null and completed
        }
        // Decode the following number of Needl passkey signatures
        else if (this.#ndlOptions.ndlCount > 0) {
            // Iterate pixels and produce valid needl keys until count is reached
            // Decoding raw data from pixels for passkey generation.

            for (let i = 0; i < this.#ndlOptions.ndlCount; i++) {
                // get initial needl key
                while (this.#byteBuffer.length < this.#ndlOptions.ndlSize) {
                    this.#iteratePixels();
                    
                    // break out condition
                    //  TODO:  Improve this breakout condition
                    if (this.#cursor.iterator.count == 1000) {
                        console.log("force loop break, while loop at 1000 iterations");
                        return false;
                    }
                }

                // Byte buffer size has been fulfilled
                let byteArray = Uint8Array.from(this.#byteBuffer.splice(0, this.#ndlOptions.ndlSize));
                let tempNeedl = new TextDecoder().decode(byteArray);

                // While Needl passkey signature value requirements are not met, re-iterate pixels until they are
                while (tempNeedl.match(/[A-Z]/g).length < this.#ndlOptions.minCapitals || tempNeedl.match(/[0-9]/g).length < this.#ndlOptions.minDigits || tempNeedl.match(/[\W_]/g).length < this.#ndlOptions.minSymbols) {
                    console.log("Missing Needl passkey signature requirements");

                    this.#iteratePixels();

                    // Check the new byte buffer for a needed value
                    for (let i = 0; i < this.#byteBuffer.length; i++) {
                        // Check for digits
                        if (tempNeedl.match(/[0-9]/g).length < this.#ndlOptions.minDigits && (this.#byteBuffer[i] >= 48 && this.#byteBuffer[i] <= 57)) {
                            // Add found digit to byteArray in a specific position
                            byteArray[this.#cursor.iterator.count % this.#ndlOptions.ndlSize] = this.#byteBuffer[i];
                        }

                        // Check for capitals
                        if (tempNeedl.match(/[A-Z]/g).length < this.#ndlOptions.minCapitals && (this.#byteBuffer[i] >= 65 && this.#byteBuffer[i] <= 90)) {
                            // Add found capital to byteArray in a specific position
                            byteArray[this.#cursor.iterator.count % this.#ndlOptions.ndlSize] = this.#byteBuffer[i];
                        }
                        
                        // Check for symbols 
                        let allowedSymbolsArray = Array.from(this.#ndlOptions.allowedSymbols, val => val.charCodeAt(0));
                        if (tempNeedl.match(/[\W_]/g).length < this.#ndlOptions.minSymbols && allowedSymbolsArray.includes(this.#byteBuffer[i])) {
                            // Add found symbol to byteArray in a specific position
                            byteArray[this.#cursor.iterator.count % this.#ndlOptions.ndlSize] = this.#byteBuffer[i];
                        }
                    }

                    // Rebuild the tempNeedl string for the next loop to check against
                    tempNeedl = new TextDecoder().decode(byteArray);
                    // Clear the byteBuffer before next loop
                    this.#byteBuffer = [];

                    // break out condition
                    //  TODO:  Improve this breakout condition
                    if (this.#cursor.iterator.count == 1000) {
                        console.log("force loop break, while loop at 1000 iterations");
                        return false;
                    }
                }

                // Requirements have been met in the tempNeedl, add value to the private class property "needl"
                this.#needl.push(tempNeedl);
                
                // Clear the buffers
                this.#base11Buffer = [];
                this.#byteBuffer = [];
            }

            return true; // when decoded enough acceptable characters into byte array to create needl and validated for requirements met
        }
        else {
            return false;
        }
    }

    #encode(dataArray) {
        // This method will encode data into pixels
    }

    #iteratePixels() {
        // Move cursor based on iterator position on x, y, and salt hashes
        let c = this.#cursor.iterator.count % Math.min(this.#cursor.iterator.x.length, this.#cursor.iterator.y.length, this.#cursor.iterator.salt.length);
        this.#cursor.currentPos.x = ((this.#cursor.currentPos.x + parseInt(this.#cursor.iterator.x.charAt(c), 16) + parseInt(this.#cursor.iterator.salt.charAt(c), 16)) * this.#cursor.modifier.multiplier) % this.#canvas.width;
        this.#cursor.currentPos.y = ((this.#cursor.currentPos.y + parseInt(this.#cursor.iterator.y.charAt(c), 16) + parseInt(this.#cursor.iterator.salt.charAt(c), 16)) * this.#cursor.modifier.multiplier) % this.#canvas.height;
        
        // Get  3x3 pixel grid from image context
        //  BUG:  iOS doesn't respect the colorspace and returns pixels values different from other systems
        let pixelGrid = this.#haystack.getImageData(this.#cursor.currentPos.x - 1, this.#cursor.currentPos.y - 1, 3, 3, { colorSpace: "srgb" });
        this.#parsePixelGrid(Array.from(pixelGrid.data));
        this.#cursor.iterator.count++;
    }

    #parsePixelGrid(pixelGridArray) {
        for (var i = 0; i < pixelGridArray.length; i++) {
            let channel = i % 4;
            // Ignore the alpha channel and the source pixel (center pixel)
            if (channel != 3 && (i < (5 * 4) || i > (5 * 4) + 3)) {
                let difference = pixelGridArray[i] - pixelGridArray[(5 * 4) + channel];
                if (Math.abs(difference) <= 5) {
                    // Valid pixel
                    this.#totalValid++;
                    let value = (difference < 0) ? 5 + Math.abs(difference) : difference;
                    this.#base11Buffer.push(value);

                    // Make sure base11Buffer doesn't start with a zero value
                    while (this.#base11Buffer[0] == 0) {
                        this.#base11Buffer.shift();
                    }
                    if (this.#base11Buffer.length >= 12) {
                        // Remove 12 elements from the base11Buffer and parse them into a base 11 value 
                        this.#parseBase11(this.#base11Buffer.splice(0, 12));
                    }
                }
                else {
                    this.#totalNotValid++;
                }
            }
        }
    }

    #parseBase11(valuesArray) {
        if (valuesArray.length == 12) {
            // Convert each value in the array to base 11 values (10 = a)
            for (var i = 0; i < 12; i++) {
                valuesArray[i] = valuesArray[i].toString(11);
            }
            let base11String = valuesArray.join("");
            let decValue = parseInt(base11String, 11);
            let base16String = decValue.toString(16);
            this.#parseBase16(base16String);
        }
    }

    #parseBase16(valuesString) {
        // Special byte will be used for calling certain function in future versions of Needl for encoding and decoding
        // Its value is either 0, 1, or 2 and comes from base 16 values after 5 bytes, essentially a "remainder" from the base 11 conversion
        let specialByte = 0;
        if (valuesString.length == 11) {
            specialByte = valuesString.substring(0, 1);
            valuesString = valuesString.substring(1);
        }

        // Check if special byte has been assigned a value of 1 or 2
        if (specialByte == 1) {
            // This pixel has been marked as unusable
            // This is used when encoding images with previous data encoded as well
            // The fifth byte position value notes the id of the decoding process it belongs to
            // If for this decoding process, pass the remaining byte values into the byteBuffer (if allowed)
            // Clear the remaining valueString before moving on
        }
        else if (specialByte == 2) {
            // Do not pass on the valueString, it will be used for instructions instead
            // This is used when encoding images to give special instructions to the decoder
            // The fifth byte position value notes the action to take
            // The remaining 4 bytes are additional instructions for that action
        }
        
        // If no special byte is present, we should have a valueString with a length of 10
        if (valuesString.length == 10) {
            let fiveBytes = valuesString.match(/([a-f\d]{2})/g);
            for (var i = 0; i < fiveBytes.length; i++) {
                let decValue = parseInt(fiveBytes[i], 16);
                // The splitByte property allows use of decimal values between 128 and 255
                if (decValue > 127 && this.#ndlOptions.splitByte) {
                    decValue -= 128;
                }
                // Check byte value with allowed characters
                // Alphabetical range:  [A-Z] ASCII(65-90) and [a-z] ASCII(97-122)
                // Numeric range:  [0-9] ASCII(48-57)
                // Default symbols:  [ !"#$%&'()*+,-./:;<=>?@[\]^_`{|}~]
                let allowedSymbolsArray = Array.from(this.#ndlOptions.allowedSymbols, val => val.charCodeAt(0));
                if (decValue >= 65 && decValue <= 90 || decValue >= 97 && decValue <= 122 || decValue >= 48 && decValue <= 57 || allowedSymbolsArray.includes(decValue)) {
                    this.#byteBuffer.push(decValue);
                }
                // This is used for decoding of previously encoded information
                if (decValue == 0) {
                    //console.log("Null found");
                }
            }
        }
    }

    async #findNeedl() {
        await this.#makeHashes();
        this.#decode();

        return this.#needl;
    }

    get results() {
        return { "iterations" : this.#cursor.iterator.count, "valid" : this.#totalValid / 3, "invalid" : this.#totalNotValid / 3, "totalPixels" : this.#canvas.width * this.#canvas.height };
    }

    get needl() {
        if (this.#needl.length != this.#ndlOptions.ndlCount) {
            // Returns a promise to resolve value
            return this.#findNeedl();
        }
        else {
            // Returns stored value
            return this.#needl;
        }
        
    }

    get filename() {
        return this.#filename;
    }

    get haystack() {
        return this.#canvas.toDataURL("image/png");
    }
}
