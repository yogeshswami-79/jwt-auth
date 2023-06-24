let refreshTokens = [];
let users = [];

function removeToken(tkn){
    refreshTokens = refreshTokens.filter(token => token != tkn);
}

module.exports = { users, refreshTokens, removeToken };