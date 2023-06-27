const mongoose = require("mongoose");
require("dotenv/config");

mongoose
    .connect("mongodb+srv://sample:qwerty123@avatarwallet.tcyin.mongodb.net/myFirstDatabase?retryWrites=true&w=majority", {
        useNewUrlParser: true,
        useUnifiedTopology: true,
    })
    .then(() => console.log("Database connected!"))
    .catch((err) => console.log(err));
mongoose.Promise = global.Promise;

module.exports = {
    Account: require("accounts/account.model"),
    Transaction: require("transactions/transaction.model"),
    RefreshToken: require("accounts/refresh-token.model"),
    isValidId,
};

function isValidId(id) {
    return mongoose.Types.ObjectId.isValid(id);
}
