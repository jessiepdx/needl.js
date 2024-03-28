/*
NEEDL:  A simple multikey password generator / manager - all from a photo
CREATED:  2018
UPDATED:  03/27/2024
VERSION:  0.1.1b
ABOUT:
    Using two simple passkeys and the photo filename to generate a hashing salt, Needl creates three unique hashes. 
    One for the x axis, one for the y axis, and one as a modififer. Think of a photo as a large two dimensional map of pixels. 
    Needl navigates through that map using coordinates that only your unique hashes can generate.
    Using the pixels at those unique coordinates, Needl calculates its own unique passkey signature. 
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
    Considering making all methods private and a single public async method that returns the needl string in a promise
TODO:
    Validation of input arguements (image size min requirements, passkey min requirements, filename min requirements)
    check for options argument object and set options accordingly (including datetime for salting)
    add encoding methods
*/
class Needl {
    // Keys and Salt
    #passkey1;
    #passkey2;
    #filename = "";

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
    #ndlSize = 128;
    // dateSalt is added to cursor.modifier
    #ndl_req = {};

    // haystack is an image file; filename, pk1, and pk2 are strings; options is a key-value pair collection (not required)
    constructor(image, fn, pk1, pk2, options = {}) {
        // Check for and uppack options here
        if (options.hasOwnProperty("ndlDate")) {
            this.#cursor.modifier.dateSalt = options.ndlDate;
        }

        // Validate data
        // Basic regular expression check
        let pk_regExp = /^[A-Za-z\d]+[A-Za-z\d. _-]{7,64}$/;
        // let fn_regExp = /^([A-Za-z\d]+( -\.[A-Za-z\d])+)\.(?:jpe?g|gif|png)$/i;
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
        if (image.width * image.height < this.#ndlSize * 1000) {
            return { "invalid" : true, "errMsg" : "not enough pixels in this image" };
        }
        
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
        this.#cursor.modifier.multiplier = saltDigits.reduce((sum, val) => sum + parseInt(val, 10), 0);

        let saltString = (this.#cursor.modifier.hasOwnProperty("dateSalt")) ? 
            saltAlpha.reduce((sum, val) => sum + val, "") + saltDigits.reduce((sum, val) => sum + val, "") + this.#cursor.modifier.dateSalt : 
            saltAlpha.reduce((sum, val) => sum + val, "") + saltDigits.reduce((sum, val) => sum + val, "");

        // Create two unique salt strings, one for each passkey
        let [pk1Salt, pk2Salt] = [...saltString].reduce((result, char, i) => (result[i%2].push(char), result), [[],[]]);
        let pk1SaltStr = pk1Salt.join("");
        let pk2SaltStr = pk2Salt.join("");

        // Hash the salt string
        const salt_charArray = new TextEncoder().encode(saltString);
        const salt_hashBuffer = await crypto.subtle.digest("SHA-256", salt_charArray);
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
        while (this.#byteBuffer.length < this.#ndlSize) {
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
        
        let byteArray = Uint8Array.from(this.#byteBuffer);
        this.#needl = new TextDecoder().decode(byteArray.slice(0, this.#ndlSize));
        
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
                if (decValue >= 33 && decValue <= 126) {
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
        if (this.#needl.length != this.#ndlSize) {
            // returns a promise to resolve value
            return this.#findNeedl();
        }
        else {
            // returns stored value
            return this.#needl;
        }
        
    }
    //  TODO:  Add two more getters:
    //  one to get regular expressions for fields for checking values in the UI
    //  and one to get the default values for options for setting up forms in UI
    //  These should be a class method and not instance method?
}
