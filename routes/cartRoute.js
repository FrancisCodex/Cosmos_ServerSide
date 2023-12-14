const express = require('express');
const router = express.Router();
const cart = require('../controllers/cart');

router.get('/view', cart.getCart);
router.post('/add', cart.addCart);
router.delete('/remove/:id', cart.deleteCartItem);
router.put('/edit/:id', cart.updateCartItem);



