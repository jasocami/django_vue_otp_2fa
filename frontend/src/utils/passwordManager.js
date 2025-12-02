export const PasswordChecker = {
    /**
     * Check if password has enough characteres
     * @param {String} pw Password to check
     */
    passwordLength(pw) {
      const checkLength = /^[A-Za-z\d#$_@!%&*?]{8,30}/;
      return checkLength.test(pw);
    },
    /**
    * Check if password contains 1 upper character
    * @param {String} pw Password to check
    */
    passwordUpper(pw) {
      const checkUpper = /^(?=.*[A-Z])/;
      return checkUpper.test(pw);
    },
    /**
    * Check if password contains 1 lower character
    * @param {String} pw Password to check
    */
    passwordLower(pw) {
      const checkLower = /^(?=.*[a-z])/;
      return checkLower.test(pw);
    },
    /**
    * Check if password contains 1 number
    * @param {String} pw Password to check
    */
    passwordNum(pw) {
      const checkNumber = /^(?=.*\d)/;
      return checkNumber.test(pw);
    },
    /**
    * Check if password contains 1 special character
    * @param {String} pw Password to check
    */
    passwordChar(pw) {
      const checkCharacter = /^(?=.*[#$.@_¡!%&*¿?])/;
      return checkCharacter.test(pw);
    },
    passwordStrong(pw) {
      const pattern = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[#$@_!%&*?])[A-Za-z\d#$_@!%&*?]{8,30}$/;
      return pattern.test(pw);
    },    
  };
  