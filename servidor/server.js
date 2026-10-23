// Política de contraseña: 8+ caracteres, minúscula, mayúscula, dígito y símbolo especial
function errorPassword(p) {
    if (typeof p !== 'string') return 'La contraseña es obligatoria';
    if (p.length > 64) return 'La contraseña no puede superar los 64 caracteres';
    const faltan = [];
    if (p.length < 8) faltan.push('mínimo 8 caracteres');
    if (!/[a-z]/.test(p)) faltan.push('una letra minúscula');
    if (!/[A-Z]/.test(p)) faltan.push('una letra mayúscula');
    if (!/\d/.test(p)) faltan.push('un dígito');
    if (!/[^A-Za-z0-9\s]/.test(p)) faltan.push('un símbolo especial');
    return faltan.length ? 'La contraseña debe tener ' + faltan.join(', ') : null;
}