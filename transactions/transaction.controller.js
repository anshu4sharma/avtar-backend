const express = require("express");
const router = express.Router();
const Joi = require("joi");
const validateRequest = require("_middleware/validate-request");
const authorize = require("_middleware/authorize");
const Role = require("_helpers/role");
const transactionService = require("./transaction.service");

// routes
router.get("/", authorize(), getAll);
router.post("/add", authorize(), addSchema, add);
router.get("/get/:id", authorize(), getById);
// router.post("/get", authorize(), getByUserIdSchema, getByUserId);
router.get("/get", authorize(), getByUserId);

module.exports = router;

function addSchema(req, res, next) {
    const schema = Joi.object({
        from: Joi.string().required(),
        to: Joi.string().required(),
        amount: Joi.string().required(),
        currency: Joi.string().required(),
        // date: Joi.date().default(new Date()),
    });
    validateRequest(req, next, schema);
    
}

function add(req, res, next) {

    transactionService
        .add({ userID: req.user.id, ...req.body })
        .then((value) => {
            console.log(value);
            res.json({
                transactionID: value.id,
                message: "Transaction registered successfully",
            });
        })
        .catch(next);
}

// function getByUserIdSchema(req, res, next) {
//     const schema = Joi.object({
//         userID: Joi.required(),
//     });
//     validateRequest(req, next, schema);
// }

function getByUserId(req, res, next) {
    transactionService
        .getByUserId(req.user.id)
        .then((transaction) => {
            res.json(transaction);
        })
        .catch(next);
}

function getById(req, res, next) {
    transactionService
        .getById(req.params.id)
        .then((transaction) => {
            res.json(transaction);
        })
        .catch(next);
}

function getAll(req, res, next) {
    // if (req.account.role === Role.Admin) {
        transactionService
            .getAll()
            .then((transactions) => res.json(transactions))
            .catch(next);
    // } else {
    //     return res.status(401).json({ message: "Unauthorized" });
    // }
}
