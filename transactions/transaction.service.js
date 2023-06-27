const db = require("_helpers/db");

module.exports = {
    add,
    getById,
    getByUserId,
    getAll,
};

async function add(params) {
    const transaction = new db.Transaction(params);
    await transaction.save();
    return transaction;
}

async function getById(id) {
    const transaction = await db.Transaction.findById(id);
    if (!transaction) throw "Transaction not found";

    return transaction;
}

async function getByUserId(userID) {
    const transactions = await db.Transaction.find({ userID: userID });
    return transactions; 
}

async function getAll() {
    const transactions = await db.Transaction.find();
    return transactions;
}
