export const validateEmail = (v: string) => v.includes('@') && !v.endsWith('@');
