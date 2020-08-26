const express = require('express');
const router = express.Router();
const auth = require('../../middleware/auth');
const Profie = require('../../models/Profile');
const User = require('../../models/User');
const { check, validationResult } = require('express-validator');
const { route } = require('./users');
const Profile = require('../../models/Profile');

/**
 * @route   GET api/profile/me
 * @desc    Get current users profile 
 * @access  Private
 */
router.get('/me', auth, async (req, res) => {
    try {
        const profile = await Profie.findOne({ user: req.user.id }).populate('user', ['name', 'avatar']);
        if(!profile) return res.status(400).json({ message: 'There is not profile for this user'});
        res.json(profile);
    } catch (error) {
        console.error(error.message);
        res.status(500).send('Server Error');
    }
});
/**
 * @route   POST api/profile/
 * @desc    Create a new user profile
 * @access  Private
 */
router.post('/', [
    auth,
    [
        check('status', 'Status is required').not().isEmpty(),
        check('skills', 'Skills is required').not().isEmpty()
    ]
], async (req, res) => {
    const errors = validationResult(req);
    if(!errors.isEmpty()) return res.status(400).json({ errors: errors.array() })
    
    const profileFields = {};
    profileFields.user = req.user.id;
    
    //Build profile object 
    const { company, website, location, bio, status, githubusername, skills} = req.body;
    if(company) profileFields.company = company;
    if(website) profileFields.website = website;
    if(location) profileFields.location = location;
    if(bio) profileFields.bio = bio;
    if(status) profileFields.status = status;
    if(githubusername) profileFields.githubusername = githubusername;
    if(skills){
        profileFields.skills = skills.split(',').map(skill => skill.trim());
    }

    //Social object
    const { youtube, facebook, twitter, instagram, linkedin } = req.body;
    profileFields.social = {};
    if(youtube) profileFields.social.youtube = youtube;
    if(twitter) profileFields.social.twitter = twitter;
    if(facebook) profileFields.social.facebook = facebook;
    if(linkedin) profileFields.social.linkedin = linkedin;
    if(instagram) profileFields.social.instagram = instagram;

    try {
        let profile = await Profie.findOne({ user: req.user.id });

        if(profile){
            profile = await Profile.findOneAndUpdate(
                { user: req.user.id },
                { $set: profileFields },
                { new: true }
            );
        }else{
            profile = new Profile(profileFields);
            await profile.save();
        }

        return res.json(profile);
    } catch (error) {
        console.error(error)
        res.status(500).send('Server Error');
    }
});

module.exports = router;