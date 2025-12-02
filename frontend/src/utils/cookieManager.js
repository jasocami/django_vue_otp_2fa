export function getAccessTokenExpiration() {
    const now = new Date();
    return new Date(now.getTime() + 60 * 60000 * 1); // 1h
  }
  
  export function getRefreshTokenExpiration() {
    const now = new Date();
    return new Date(now.getTime() + 7 * 24 * 60 * 60000); // 7 dias
  }
  
  export function setCookie(name, value, expiration) {
    let expires = "";
    if (expiration) {
      expires = "; expires=" + expiration.toUTCString();
    }
    document.cookie = name + "=" + (value || "") + expires + "; path=/; Secure; SameSite=Lax";
  }
  
  export function getCookie(name) {
    const nameEQ = name + "=";
    const ca = document.cookie.split(';');
    for (let i = 0; i < ca.length; i++) {
      let c = ca[i];
      while (c.charAt(0) === ' ') c = c.substring(1, c.length);
      if (c.indexOf(nameEQ) === 0) return c.substring(nameEQ.length, c.length);
    }
    return null;
  }
  
  export function removeCookies() {
    var Cookies = document.cookie.split(';');
    for (var i = 0; i < Cookies.length; i++)
      document.cookie = Cookies[i] + "=;expires=" + new Date(0).toUTCString();
  }