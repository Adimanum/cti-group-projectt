// ordinary use of JS Proxy for form validation
const handler = { set(o, k, v) { if (!v) throw new Error(k + ' required'); o[k] = v; return true; } };
const form = new Proxy({}, handler);
form.email = 'user@example.invalid';
