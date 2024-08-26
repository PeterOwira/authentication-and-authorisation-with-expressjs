const jwt = require("jsonwebtoken");
require("dotenv").config();
const config = process.env;

const authorisation = (requiredRole) => {
	
    return (req, res, next) => {
        try {
            const userCookies = req.signedCookies;
            const xAccessToken = userCookies?.user?.token;
            console.log(xAccessToken)

            if (!xAccessToken) {
                console.log("No access token provided.");
                return res.status(401).send({
                    auth: false,
                    message: "Missing access token.",
                    status: 401,
                    payload: null,
                });
            }

            console.log("Access Token:", xAccessToken);

            // Verify the token
            const decoded = jwt.verify(xAccessToken, config.TOKEN_KEY);
            console.log("Decoded Token:", decoded);

            const userRole = decoded.user?.account_type;

            if (!userRole) {
                console.log("No account_type found in token.");
                return res.status(403).send({
                    auth: false,
                    message: "User role not found in token.",
                    status: 403,
                    payload: null,
                });
            }

            console.log("User Role:", userRole, "Required Role:", requiredRole);

            if (convertToRole(userRole) < convertToRole(requiredRole)) {
                console.log("User role insufficient.");
                return res.status(403).send({
                    auth: false,
                    message: "You are not authorised to access this page.",
                    status: 403,
                    payload: null,
                });
            }

            // If everything is okay, proceed to the next middleware
            return next();

        } catch (error) {
            console.error("Authorization error:", error.message);
            return res.status(401).send({
                auth: false,
                message: "Invalid or expired token.",
                status: 401,
                payload: null,
            });
        }
    };
};

// Converts role string to a numerical value for comparison
const convertToRole = (role) => {
    switch (role) {
        case "user":
            return 1;
        case "admin":
            return 2;
        default:
            return 0; // Unknown role or no role should be treated as least privileged
    }
}

module.exports = authorisation;