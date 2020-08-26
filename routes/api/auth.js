const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const config = require('config');
const { check, validationResult } = require('express-validator');
const auth = require('../../middleware/auth');
const User = require('../../models/User');

/**
 * @route   GET api/auth
 * @desc    Test 
 * @access  Public
 */
router.get('/', auth, async (req, res) => {
    try{
        const user = await User.findById(req.user.id).select('-password');
        res.json(user)
    }catch(error){
        console.error(error.message);
        res.status(500).json({
            message: 'Server error'
        });
    }
});

/**
 * @route   POST api/auth/
 * @desc    Auth and get token 
 * @access  Public
 */
router.post('/', [ 
    check('email', 'Please include a valid email').isEmail(),
    check('password', 'Password is required').exists()
], async (req, res) => {
    /* Validate body */
    const error = validationResult(req);
    if(!error.isEmpty()) return res.status(400).json({ errors: error.array() });

    const { email, password } = req.body;
    
    try {
        /* Find user */
        let user = await User.findOne({ email });
        if(!user) return res.status(400).json({ errors: [{ message: 'Invalid credentials' }]});
        
        const isMatch = await bcrypt.compare(password, user.password);
        if(!isMatch) return res.status(400).json({ errors: [{ message: 'Invalid credentials' }]});
         
        user.lastLogin = Date.now();
        user.save();

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

module.exports = router;