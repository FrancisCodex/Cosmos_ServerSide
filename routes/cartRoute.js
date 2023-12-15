const express = require('express');
const router = express.Router();
const cart = require('../controllers/cart');
const {checkRole} = require('../middleware/auth');
const verifyRole = require('../middleware/verifyToken');

router.get('/view', verifyRole, cart.getCart);
router.post('/add', verifyRole, cart.addCart);
router.delete('/remove/:id', verifyRole, cart.deleteCartItem);




module.exports = router;