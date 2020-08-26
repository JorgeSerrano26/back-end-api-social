const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const gravatar = require('gravatar');
const jwt = require('jsonwebtoken');
const config = require('config');
const { check, validationResult } = require('express-validator');

const User = require('../../models/User');

/**
 * @route   POST api/users
 * @desc    Register user 
 * @access  Public
 */
router.post('/', [ 
    check('name', 'Name is required').not().isEmpty(),
    check('email', 'Please include a valid email').isEmail(),
    check('password', 'Please enter a password with 6 or more characters').isLength({min: 6})
], async (req, res) => {
    /* Validate body */
    const error = validationResult(req);
    if(!error.isEmpty()) return res.status(400).json({ errors: error.array() });

    const { name, email, password } = req.body;
    
    try {
        /* Find user */
        let user = await User.findOne({ email });
        if(user){
           return res.status(400).json({ errors: [{ message: 'User already exists' }]});
        }
        
        /* Generate avatar*/
        const avatar = gravatar.url(email, {
            s: '200',
            r: 'pg',
            d: 'mm'
        });

        /* Hashing password*/
        const salt = await bcrypt.genSalt(10);
        const passwordHash = await bcrypt.hash(password, salt);

        /* Creat user */
        user = new User({
            name,
            email,
            avatar,
            password: passwordHash
        });
        
        /* Save user */
        await user.save();

        /* Return JWT */
        const payload = {
            user: {
                id: user.id
            }
        };

        jwt.sign(payload, config.get('jwtSecret'), {
            expiresIn: 360000
        }, (err, token) => {
            if(err) throw err;
            res.status(201).json({ token });
        });
    } catch (error) {
        console.error(error.message);
        res.status(500).send('Server error');
    }
    
});
/**
 * @route   GET api/users
 * @desc    Get users 
 * @access  Public
 */
router.get('/', (req, res) => {
    res.send({ 
        message: "Users",
        statusCode: 200
    })
});

module.exports = router;