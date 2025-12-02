const API_BASE_URL = import.meta.env.VITE_APP_BASE_URL;

const defaultHeaders = (authorization) => ({
  Authorization: `Bearer ${authorization}`,
  'Content-Type': 'application/json',
});

export {
  API_BASE_URL,
  defaultHeaders,
};