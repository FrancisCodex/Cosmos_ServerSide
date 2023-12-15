const pool = require('../config/database')
const dotenv = require('dotenv');
const jwt = require('jsonwebtoken');
dotenv.config();


exports.getCart = (req, res) => {
    //api call to get all the cart items of the user
    const authHeader = req.headers.authorization;
    const token = authHeader && authHeader.split(' ')[1];
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user_id = decoded.userId;

    pool.query('SELECT *, product_quantity * product_price AS subtotal FROM cosmos.get_order_details($1);', [user_id], (error, results) => {
        if (error) {
            throw error
        }

        if(results.rows.length === 0){
            return res.status(404).json({ message: 'No items in cart' });
        }

        res.status(200).json(results.rows)
    })
}

exports.addCart = (req, res) => {
    const authHeader = req.headers.authorization;
    const token = authHeader && authHeader.split(' ')[1];

    if (token == null) return res.sendStatus(401); // if there isn't any token

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
    });

    const { product_id, qty } = req.body;
    const user_id = req.user.userId; // get user id from decoded token

    pool.query('SELECT * FROM cosmos.order_items WHERE product_id = $1 AND user_id = $2', [product_id, user_id], (error, results) => {
        if (error) {
            throw error;
        }

        if (results.rows.length > 0) {
            // If the product is already in the cart, update the quantity
            pool.query('UPDATE cosmos.order_items SET qty = qty + 1 WHERE product_id = $1 AND user_id = $2', [product_id, user_id], (error, results) => {
                if (error) {
                    throw error;
                }
                console.log("Cart updated");
                res.status(200).send(`Cart updated`);
            });
        } else {
            // If the product is not in the cart, add it
            pool.query('INSERT INTO cosmos.order_items (product_id, user_id, qty) VALUES ($1, $2, $3)', [product_id, user_id, qty], (error, results) => {
                if (error) {
                    throw error;
                }
                console.log("Cart Added item");
                res.status(201).send(`Cart added`);
            });
        }
    });
};

exports.deleteCartItem = (req, res) => {
    const {id} = req.params

    pool.query('DELETE FROM cosmos.order_items WHERE order_item_id = $1', [id], (error, results) => {
        if (error) {
            throw error
        }
        res.status(200).send(`Cart deleted with ID: ${id}`)
    })
}



