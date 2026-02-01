import Cookies from 'js-cookie';

export default {
  name: 'cookieManager',
  transformToHuman(val, t) {
    if ([undefined, null].includes(val)) return val;
    if (t === Boolean) return (val.toLowerCase() === 'true');
    if (t === Number) return (parseInt(val, 10));
    return val;
  },
  getCookieExpiration() {
    // Return a expiration date 24h from now
    const now = new Date();
    return new Date(now.getTime() + 60 * 60000 * 24);
  },
  // cookieAsObject(cookie) {
  //   return cookie.split(/[;] */).reduce((result, pairStr) => {
  //     const arr = pairStr.split('=');
  //     const [key, value] = arr;
  //     if (arr.length === 2) {
  //       result[key] = value; // eslint-disable-line no-param-reassign
  //     }
  //     return result;
  //   }, {});
  // },
  set(name, value, expiration) {
    // eslint-disable-next-line
    if (!expiration) expiration = this.getCookieExpiration();
    // eslint-disable-next-line
    expiration = expiration.toUTCString();
    document.cookie = `${name}=${value}; expires=${expiration}; path=/; Secure; SameSite=Lax;`;
  },
  get(name, t = String) {
    const val = Cookies.get(name);
    console.log(name, val, t);
    if (!val) return null;
    return this.transformToHuman(val, t);
  },
  /**
   * Set OTP verification status cookie
   * @param {boolean} value - Whether OTP is verified
   */
  setOtpVerified(value) {
    this.set('otp_verified', value ? 'true' : 'false');
  },
  /**
   * Check if OTP has been verified for current session
   * @returns {boolean} True if OTP is verified
   */
  hasOtpVerified() {
    return this.get('otp_verified') === 'true';
  },
  delete(name) {
    Cookies.delete(name);
  },
  deleteAll() {
    document.cookie.split(';').forEach((c) => {
      document.cookie = `${c.trim().split('=')[0]}=; expires=Thu, 01 Jan 1970 00:00:00 GMT;`;
    });
    localStorage.clear();
  },
};
