/*
NEEDL:  A simple multikey password generator / manager - all from a photo
CREATED:  2018
UPDATED:  04/02/2024
VERSION:  0.1.3b
ABOUT:
    Using two simple passkeys and the photo filename to generate a hashing salt, Needl creates three unique hashes. 
    One for the x axis, one for the y axis, and one as a modififer. Think of a photo as a large two dimensional map of pixels. 
    Needl navigates through that map using coordinates that only your unique hashes can generate.
    Using the pixels at those unique coordinates, Needl's algorithm calculates its own unique passkey signature. 
    Now anytime you need to retrieve that passkey, you just need that photo, and your two passkeys.
    Example:
        Photo00179.jpg (this string itself is a part of salt string)
        passkey1:  "First hike with puppy"  (each of these passkeys are salted as well)
        passkey2:  "personal instagram"
    Only this unique map of pixels, and three unique keys:  passkey1, passkey2, and filename (with datetime options for additional unique salting)
    will retrieve that same unique passkey signature. Use the same combination but a different string for passkey2, for example - "work instagram", 
    you will get a completely different and unique passkey signature.
    Like finding a needle in a haystack.

    For more information, visit:  https://github.com/jessiepdx/needl.js
NOTES:
    
TODO:
    Improved validation of input arguements (image size min requirements, passkey min requirements, filename min requirements)
    Add an array that contains all acceptable characters in byte value to check for valid bytes to return to the byte array
    Separate out iteratePixels and create buildNeedl (which will call iteratePixels and validate the string)
    Add a second argument to iteratePixels that takes an array of acceptable byte values to add to the byte array
    Add encoding method (in version 2)
*/

// Available outside of the class for accessing by UI inputs
//  TODO:  Set all these up correctly
const symbol_sets = {
    "full" : "!@#$%^&*()-_+=`~.,<>/?\";:[]{}",
    "partial" : "",
    "minimal" : ""
};

// Defaults set here overwrite the Needl class defaults.
const needl_defaults = {
    "ndlSize" : 128,
    "minCapitals" : 1,
    "minDigits" : 1,
    "minSymbols" : 1,
    "allowedSymbols" : symbol_sets.full
};

class Needl {
    // Keys and Salt
    #passkey1;
    #passkey2;
    #filename = "";
    // dateSalt is added to cursor.modifier

    // Haystack and Needl
    #canvas = document.createElement("canvas");
    #haystack = this.#canvas.getContext("2d", { willReadFrequently: true });
    #cursor = { "start" : {}, "iterator" : {}, "modifier" : {} };
    #needl = "";

    // Buffers to hold values
    #base11Buffer = [];
    #byteBuffer = [];

    // Results data
    #totalValid = 0;
    #totalNotValid = 0;

    // Options
    #ndlOptions = {
        "ndlSize" : 128,
        "minCapitals" : 1,
        "minDigits" : 1,
        "minSymbols" : 1,
        "allowedSymbols" : "!@#$%^&*()-_+=`~.,<>/?\";:[]{}"
    };

    // haystack is an image file; filename, pk1, and pk2 are strings; options is a key-value pair collection (not required)
    constructor(image, fn, pk1, pk2, options = {}) {
        // Merge options with needl_defaults and overwrite with assigned values
        this.#ndlOptions = {...needl_defaults, ...options};
        // Add the date modifier if set in options
        if (options.hasOwnProperty("ndlDate")) {
            this.#cursor.modifier.dateSalt = options.ndlDate;
        }

        // Validate data
        // Basic regular expression check
        let pk_regExp = /^[A-Za-z\d]+[A-Za-z\d. _-]{7,64}$/;
        let fn_regExp = /^[A-Za-z\d]+[A-Za-z\d. _-]{7,64}(.jpe?g|.gif|.png|.bmp)$/;
        
        // test for required arguments
        if (!image || !pk1 || !pk2) {
            return { "invalid" : true, "errMsg" : "missing required arguments" };
        }
        // test for valid arguements
        if (!pk_regExp.test(pk1) || !pk_regExp.test(pk2)) {
            return { "invalid" : true, "errMsg" : "passkeys requirements not met" };
        }

        // test for valid filename
        if (!fn_regExp.test(fn)) {
            return { "invalid" : true, "errMsg" : "filename requirements not met" };
        }

        // test for minimum pixel count
        //  TODO:  will improve this later
        if (image.width * image.height < this.#ndlOptions.ndlSize * 1000 * 9) {
            return { "invalid" : true, "errMsg" : "not enough pixels in this image" };
        }
        
        // Everything is valid - draw image in canvas and set properties
        this.#haystack.canvas.width = image.width;
        this.#haystack.canvas.height = image.height;
        this.#haystack.drawImage(image, 0, 0);
        this.#filename = fn;
        this.#passkey1 = pk1;
        this.#passkey2 = pk2;
    }

    // Using javascript's SubleCrypto functions are asyncronous and cannot be called within the constructor
    // Therefore a method to create the hashes is called separately
    async #makeHashes() {
        // First create a salt from filename
        let saltAlpha = this.#filename.match(/[A-Za-z]/g);
        let saltDigits = this.#filename.match(/\d/g);
        // extract all digits from dateSalt if it exist, otherwise saltDate is an empty array
        let saltDate = (this.#cursor.modifier.hasOwnProperty("dateSalt")) ? this.#cursor.modifier.dateSalt.match(/\d/g) : [];
        // multiplier is the sum of each individual digit from saltDigits and saltDate
        this.#cursor.modifier.multiplier = saltDigits.reduce((sum, val) => sum + parseInt(val, 10), 0) + saltDate.reduce((sum, val) => sum + parseInt(val, 10), 0);

        let saltString = saltAlpha.reduce((sum, val) => sum + val, "") + saltDigits.reduce((sum, val) => sum + val, "") + saltDate.reduce((sum, val) => sum + val, "");

        // Create two unique salt strings, one for each passkey
        let [pk1Salt, pk2Salt] = [...saltString].reduce((result, char, i) => (result[i%2].push(char), result), [[],[]]);
        let pk1SaltStr = pk1Salt.join("");
        let pk2SaltStr = pk2Salt.join("");

        // Hash the salt string
        const salt_charArray = new TextEncoder().encode(saltString);
        taConsole("trying first hash...");
        const salt_hashBuffer = await crypto.subtle.digest("SHA-256", salt_charArray);
        taConsole(" first hash complete!\n");
        const salt_hashArray = Array.from(new Uint8Array(salt_hashBuffer));

        // convert hash array data into 64 character string of hexidecimals
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

    #iteratePixels() {
        // set current cursor position to the start x and y
        let currentPos = { 
            "x" : (this.#cursor.start.x * this.#cursor.modifier.multiplier) % this.#canvas.width, 
            "y" : (this.#cursor.start.y * this.#cursor.modifier.multiplier) % this.#canvas.height };
        
        // Iterate pixels until satifying desired "needle" passcode length
        this.#cursor.iterator.count = 0;
        // Will need to eventually move this loop into a separate own method
        while (this.#byteBuffer.length < this.#ndlOptions.ndlSize) {
            // move cursor based on iterator position on x, y, and salt hashes
            let c = this.#cursor.iterator.count % Math.min(this.#cursor.iterator.x.length, this.#cursor.iterator.y.length, this.#cursor.iterator.salt.length);
            currentPos.x = ((currentPos.x + parseInt(this.#cursor.iterator.x.charAt(c), 16) + parseInt(this.#cursor.iterator.salt.charAt(c), 16)) * this.#cursor.modifier.multiplier) % this.#canvas.width;
            currentPos.y = ((currentPos.y + parseInt(this.#cursor.iterator.y.charAt(c), 16) + parseInt(this.#cursor.iterator.salt.charAt(c), 16)) * this.#cursor.modifier.multiplier) % this.#canvas.height;
            
            // Get  3x3 pixel grid from image context
            let pixelGrid = this.#haystack.getImageData(currentPos.x - 1, currentPos.y - 1, 3, 3);
            //console.log(pixelGrid);
            this.#parsePixelGrid(Array.from(pixelGrid.data));
            this.#cursor.iterator.count++;
            
            // Back up condition to break the loop with an error
            //  TODO:  Improve this.
            if (this.#cursor.iterator.count == 1000) {
                console.log("had to break");
                break;
            }
        }
        
        // Byte buffer size has been fulfilled
        let byteArray = Uint8Array.from(this.#byteBuffer.splice(0, this.#ndlOptions.ndlSize));
        let tempNeedl = new TextDecoder().decode(byteArray);
        console.log(tempNeedl);

        // Validate required number of capital letters and digits
        /* DISPLAY FOR DEBUGGING
        let capitalMatches = tempNeedl.match(/[A-Z]/g);
        let digitMatches = tempNeedl.match(/[0-9]/g);
        let symbolMatches = tempNeedl.match(/[\W_]/g);
        console.log("Min capitals:  " + this.#ndlOptions.minCapitals);
        console.log("Capital letters:  " + capitalMatches.length);
        console.log("Min digits:  " + this.#ndlOptions.minDigits);
        console.log("Digit count:  " + digitMatches.length);
        console.log("Min symbols:  " + this.#ndlOptions.minSymbols);
        console.log("Symbol count:  " + symbolMatches.length);
        */

        // Re-iterate pixels until requirements are satified
        while (tempNeedl.match(/[A-Z]/g).length < this.#ndlOptions.minCapitals || tempNeedl.match(/[0-9]/g).length < this.#ndlOptions.minDigits || tempNeedl.match(/[\W_]/g).length < this.#ndlOptions.minSymbols) {
            console.log("Missing string requirements");
            
            // move cursor based on iterator position on x, y, and salt hashes
            let c = this.#cursor.iterator.count % Math.min(this.#cursor.iterator.x.length, this.#cursor.iterator.y.length, this.#cursor.iterator.salt.length);
            currentPos.x = ((currentPos.x + parseInt(this.#cursor.iterator.x.charAt(c), 16) + parseInt(this.#cursor.iterator.salt.charAt(c), 16)) * this.#cursor.modifier.multiplier) % this.#canvas.width;
            currentPos.y = ((currentPos.y + parseInt(this.#cursor.iterator.y.charAt(c), 16) + parseInt(this.#cursor.iterator.salt.charAt(c), 16)) * this.#cursor.modifier.multiplier) % this.#canvas.height;
            
            // Get  3x3 pixel grid from image context
            let pixelGrid = this.#haystack.getImageData(currentPos.x - 1, currentPos.y - 1, 3, 3);
            this.#parsePixelGrid(Array.from(pixelGrid.data));
            this.#cursor.iterator.count++;

            // Check the new byte buffer for needed value
            for (let i = 0; i < this.#byteBuffer.length; i++) {
                // Check for digits
                if (tempNeedl.match(/[0-9]/g).length < this.#ndlOptions.minDigits && (this.#byteBuffer[i] >= 48 && this.#byteBuffer[i] <= 57)) {
                    // Found a digit
                    console.log("found a digit");
                    // Add found digit to byteArray in a specific position
                    byteArray[this.#cursor.iterator.count % this.#ndlOptions.ndlSize] = this.#byteBuffer[i];
                }

                // Check for capitals
                if (tempNeedl.match(/[A-Z]/g).length < this.#ndlOptions.minCapitals && (this.#byteBuffer[i] >= 65 && this.#byteBuffer[i] <= 90)) {
                    // Found a capital
                    console.log("found a capital");
                    // Add found capital to byteArray in a specific position
                    byteArray[this.#cursor.iterator.count % this.#ndlOptions.ndlSize] = this.#byteBuffer[i];
                }
                
                // Check for symbols 
                let allowedSymbolsArray = Array.from(this.#ndlOptions.allowedSymbols, val => val.charCodeAt(0));
                if (tempNeedl.match(/[\W_]/g).length < this.#ndlOptions.minSymbols && allowedSymbolsArray.includes(this.#byteBuffer[i])) {
                    // Found a symbol
                    console.log("found a symbol");
                    // Add found symbol to byteArray in a specific position
                    byteArray[this.#cursor.iterator.count % this.#ndlOptions.ndlSize] = this.#byteBuffer[i];
                }
            }

            // Rebuild the tempNeedl string
            tempNeedl = new TextDecoder().decode(byteArray);
            // Clear the byteBuffer before next loop
            this.#byteBuffer = [];

            // Back up condition to break the loop with an error
            //  TODO:  Improve this.
            if (this.#cursor.iterator.count == 1000) {
                console.log("had to break");
                break;
            }
        }
        // Requirements have been met in the tempNeedl, set the private class property "needl"
        this.#needl = tempNeedl;
        
        // Clear the buffers
        this.#base11Buffer = [];
        this.#byteBuffer = [];
    }

    #parsePixelGrid(pixelGridArray) {
        for (var i = 0; i < pixelGridArray.length; i++) {
            let channel = i % 4;
            // ignore the alpha channel and the source pixel (center pixel)
            if (channel != 3 && (i < (5 * 4) || i > (5 * 4) + 3)) {
                let difference = pixelGridArray[i] - pixelGridArray[(5 * 4) + channel];
                if (Math.abs(difference) <= 5) {
                    // valid pixel
                    this.#totalValid++;
                    let value = (difference < 0) ? 5 + Math.abs(difference) : difference;
                    this.#base11Buffer.push(value);

                    // make sure base11Buffer doesn't start with a zero value
                    while (this.#base11Buffer[0] == 0) {
                        this.#base11Buffer.shift();
                    }
                    if (this.#base11Buffer.length >= 12) {
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
        // special byte will be used for calling certain function in future versions of Needl for encoding and decoding
        // its value is either 0, 1, or 2 and comes from base 16 values after 5 bytes
        // essentially a "remainder" from the base 11 conversion
        let specialByte = 0;
        if (valuesString.length == 11) {
            specialByte = valuesString.substring(0, 1);
            valuesString = valuesString.substring(1);
        }
        if (valuesString.length == 10) {
            let fiveBytes = valuesString.match(/([a-f\d]{2})/g);
            
            for (var i = 0; i < fiveBytes.length; i++) {
                let decValue = parseInt(fiveBytes[i], 16);
                // Check byte value with allowed characters
                // Alphabetical range:  [A-Z] ASCII(65-90) and [a-z] ASCII(97-122)
                // Numeric range:  [0-9] ASCII(48-57)
                // Default symbols:
                let allowedSymbolsArray = Array.from(this.#ndlOptions.allowedSymbols, val => val.charCodeAt(0));
                if (decValue >= 65 && decValue <= 90 || decValue >= 97 && decValue <= 122 || decValue >= 48 && decValue <= 57 || allowedSymbolsArray.includes(decValue)) {
                    this.#byteBuffer.push(decValue);
                }
            }
        }
        else {
            console.log("incompatible value string:  " + valuesString);
        }
    }

    async #findNeedl() {
        await this.#makeHashes();
        this.#iteratePixels();

        return this.#needl;
    }

    get results() {
        return { "iterations" : this.#cursor.iterator.count, "valid" : this.#totalValid / 3, "invalid" : this.#totalNotValid / 3, "totalPixels" : this.#canvas.width * this.#canvas.height };
    }

    get needl() {
        if (this.#needl.length != this.#ndlOptions.ndlSize) {
            // returns a promise to resolve value
            return this.#findNeedl();
        }
        else {
            // returns stored value
            return this.#needl;
        }
        
    }
}
