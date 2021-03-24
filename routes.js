const express = require('express');
const router = express.Router();


//##### Auth #####
const bcrypt = require("bcrypt");
const User = require("./models/user");

const jwt = require("jsonwebtoken");
require("dotenv").config();

const auth = require('./middleware/auth')

const {check, validationResult} = require('express-validator');


router.post('/create-user', [
    check('name').notEmpty().withMessage('Name is required').trim().escape(),
    check('email', 'Email is required').isEmail().normalizeEmail(),
    check('password', 'Password is required').isLength({min: 4}).custom((val, {req}) => {
        if(val !== req.body.confirm_password) {
            throw new Error(`Password don't match!`);
        } else {
            return val;
        }
    })
], (req, res) => {
    const errors = validationResult(req).array();
    console.log(errors);
    if(errors.length>0){
        req.session.errors = errors;        
        res.redirect('/user');
    } else {
        //res.redirect('/');

        //############# Auth ################
        User.find({ email: req.body.email })
            .exec()
            .then(user => {
                console.log(user);
                if (user.length >= 1) {
                    return res.status(409).json({
                        message: "Mail exists"
                    });
                } else {
                    bcrypt.hash(req.body.password, 10, (err, hash) => {
                        if (err) {
                            return res.status(500).json({
                                error: err
                            });
                        } else {
                            
                            const user = new User({
                                name: req.body.name,
                                email: req.body.email,
                                password: hash
                            });
                            user
                                .save()
                                .then(result => {
                                    console.log(result.name);
                                    const userName = result.name;
                                    res.render('welcome', {userName});
                                    // If you want to use the object literal shorthand you need to use the object brackets around name so it knows you are passing an object and not just the variable name.
                                    // res.status(201).json({
                                    //     message: "User created"
                                    // });
                                })
                                .catch(err => {
                                    console.log(err);
                                    res.status(500).json({
                                        error: err
                                    });
                                });
                        }
                    });
                }
            });

    }
});

router.get('/user', function(req, res){
    res.render('user', {errors: req.session.errors});
});

///Login
router.get('/login', function(req, res){
    res.render('login');
});

router.post('/login', (req, res) => {    
    User.find({ email: req.body.email })
        .exec()
        .then(user => {
            if (user.length < 1) {
                return res.status(401).json({
                    message: "Auth failed"
                });
            }
            bcrypt.compare(req.body.password, user[0].password, (err, result) => {
                if (err) {
                    return res.status(401).json({
                        message: "Auth failed"
                    });
                }
                if (result) {
                    const token = jwt.sign(
                        {
                            email: user[0].email,
                            userId: user[0]._id
                        },
                        process.env.JWT_KEY,
                        {
                            expiresIn: "1h"
                        }
                    );
                    //return res.render('welcome');
                    return res.status(200).json({
                        message: "Auth successful",
                        token: token
                    });
                }
                res.status(401).json({
                    message: "Auth failed"
                });
            });
        })
        .catch(err => {
            console.log(err);
            res.status(500).json({
                error: err
            });
        });

    
});



router.delete("/:userId", auth, (req, res) => {
    User.remove({ _id: req.params.userId })
        .exec()
        .then(result => {
            res.status(200).json({
                message: "User deleted"
            });
        })
        .catch(err => {
            console.log(err);
            res.status(500).json({
                error: err
            });
        });
});


router.get('/create-user', function(req, res) {
    res.render('user');    
});

module.exports = router;