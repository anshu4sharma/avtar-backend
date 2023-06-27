const { ObjectId } = require("mongoose");
const mongoose = require("mongoose");
const Schema = mongoose.Schema;

const schema = new Schema({
    userID: {
        type: ObjectId,
        required: true,
    },
    from: {
        type: String,
        required: true,
    },
    to: {
        type: String,
        required: true,
    },
    amount: {
        type: String,
        required: true,
    },
    currency: {
        type: String,
        required: true,
    },
    date: {
        type: Date,
        // required: true,
        default: Date.now,
    },
    updated: Date,
});

module.exports = mongoose.model("Transaction", schema);
