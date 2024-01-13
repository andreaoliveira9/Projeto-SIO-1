# DETI Store

## Description

Welcome to DETI Store, your one-stop destination for a feature-rich online shopping experience. We've integrated a diverse array of functionalities to ensure your shopping is both effortless and convenient. Here's an overview of what you can anticipate:

1. User Management:

   - User Registration and Login: Begin your journey by creating a user account, or if you're a returning customer, simply log in for a personalized experience.
   - User Profiles: Manage your personal information and preferences, ensuring a tailored shopping experience.
   - Password Management: Reset forgotten passwords and change them securely to keep your account safe.
   - User Roles and Permissions: Admins have special privileges to manage the platform efficiently.

2. Product Catalog:

   - Product Listings with Details: Explore our extensive product listings, each complete with essential information such as product name, description, price, and high-quality images.
   - Product Categories and Filters: Find products effortlessly with our well-organized categories and user-friendly filters.
   - Product Search Functionality: Looking for a specific item? Our search feature will help you find it in no time.

3. Shopping Cart:

   - Cart Management: Add, remove, or update items in your shopping cart as you shop. Your cart, your control.
   - Cart Total Calculation: Never be surprised by the cost. Our system calculates the total amount in your cart as you shop.
   - Save Cart for Later or Wish List: If you're not ready to make a purchase, save your cart or create a wish list for future reference.

4. Checkout Process:

   - Shipping and Billing Information Collection: Provide the necessary details for smooth order processing, including shipping and billing information.
   - Payment Processing: We accept various payment methods, including credit cards, PayPal, and more, ensuring a secure and convenient transaction.
   - Order Confirmation and Receipt Generation: You'll receive a confirmation of your order and a receipt for your records.

5. Inventory Management:

   - Tracking Product Availability: We keep you informed about product availability, letting you know whether an item is in-stock or out-of-stock.
   - Managing Product Quantities: We track product quantities to ensure accurate stock levels and update them as items are purchased.

6. Order History:

   - View and Track Past Orders: Access your order history to review past purchases and check the status of current orders.
   - Reorder from Order History: Reorder products you've purchased before with a single click, saving you time and effort.

7. Reviews and Ratings:

   - Allow Customers to Rate and Review Products: Share your thoughts with other shoppers by leaving product reviews and ratings.
   - Display Average Ratings and Reviews: Get insights from fellow customers with average product ratings and individual product reviews.

Our DETI Store is meticulously crafted to elevate your shopping experience, offering a user-friendly interface, efficient features, and top-notch customer service. Explore a wide selection of products, conduct secure transactions, and relish the convenience of online shopping, all within a single destination. Start shopping with us today!

## Authors

- André Oliveira **107637**
- Duarte Cruz **107359**
- Zé Mendes **107188**
- Filipe Obrist **107471**

## Vulnerability

- **CWE - 89** - Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')
- **CWE - 79** - Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')
- **CWE - 352** - Cross-Site Request Forgery (CSRF)
- **CWE - 488** - Exposure of Data Element to Wrong Session
- **CWE - 798** - Use of Hard-coded Credentials
- **CWE - 620** - Unverified Password Change
- **CWE - 521** - Weak Password Requirements
- **CWE - 522** - Insufficiently Protected Credentials
- **CWE - 434** - Unrestricted Upload of File with Dangerous Type

## Execute

### Docker

To run in docker you need just have to run the following command inside the version you want to run and execute

```bash
docker-compose up
```

The insecure version will be running on port 8000 and the secure version will be running on port 8080 you may cahnfe the port in the docker-compose.yml file

### Venv

#### Create

```bash
python3.11 -m venv venv
```

#### Activate and install requirements

```bash
source venv/bin/activate
pip install -r requirements.txt
```

### Local

To run locally you must use the **run.sh** with the params -a and -p to specify the version and port you want to run the application.

Example for app:

```bash
./run.sh -a app -p 8080
```

Example for app_sec:

```bash
./run.sh -a app_sec -p 8080
```

### CSRF

With the unsafe version of the app running, run the following command in another terminal in the analysis directory:

```shell
python3 -m http.server --directory . <PORT>
```

Note: the scam site will only be visible on 127.0.0.1:<PORT>.

**IMPORTANT**
When you start the application for the first time you must run the following url to populate the database:

- http://127.0.0.1:8080/generate/database
