const pool = require('../config/database')
const dotenv = require('dotenv');
dotenv.config();


exports.checkoutItems = (req, res) => {
    //api call to store the products that the user wants to buy
    //the products will be sent to the orders table
    const { product_id, user_id, quantity } = req.body
    try{
        pool.query('INSERT INTO cosmos.orders (product_id, user_id, quantity) VALUES ($1, $2, $3)', [product_id, user_id, quantity], (error, results) => {        
        res.status(201).send(`Order added with ID: ${results.insertId}`)
        })
    }catch(error){
        res.status(500).json({ message: 'Server Error' });
    }
}

exports.getAllOrder = async (req, res) => {
    const {id} = req.params

    try{
    pool.query('')
    }catch(error){

    }
}
