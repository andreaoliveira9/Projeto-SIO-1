from flask import Blueprint, render_template, redirect, url_for, request, flash
from flask_login import login_required, current_user
from sqlalchemy import text
from .models import User
from . import db
import os

profile = Blueprint("profile", __name__)


@profile.route("/profile")
@login_required
def perfil():
    user = User.query.filter_by(id=current_user.id).first()

    # get number of items in cart
    query = text("SELECT * FROM cart WHERE customer_id =" + str(current_user.id))

    cart = db.session.execute(query).fetchone()

    if cart is not None:
        query = text("SELECT COUNT(*) FROM cart_product WHERE cart_id =" + str(cart.id))
        number_of_items = db.session.execute(query).fetchone()[0]
    else:
        number_of_items = 0

    return render_template(
        "my-account.html", user=user, number_of_items=number_of_items
    )


@profile.route("/profile/<int:id>", methods=["GET"])
@login_required
def changeProfile(id):
    user = User.query.filter_by(id=id).first()

    # get number of items in cart
    query = text("SELECT * FROM cart WHERE customer_id =" + str(current_user.id))

    cart = db.session.execute(query).fetchone()

    if cart is not None:
        query = text("SELECT COUNT(*) FROM cart_product WHERE cart_id =" + str(cart.id))
        number_of_items = db.session.execute(query).fetchone()[0]
    else:
        number_of_items = 0

    return render_template("profile.html", user=user, number_of_items=number_of_items)


@profile.route("/profile/<int:id>", methods=["POST"])
@login_required
def changeProfileForm(id):
    user = User.query.filter_by(id=id).first()
    name = request.form.get("name")
    username = request.form.get("username")
    phone = request.form.get("phone")
    image = request.files.get("image")
    newPassword = request.form.get("newPassword")
    confirmNewPassword = request.form.get("confirmNewPassword")

    if name:
        user.name = name
    if username:
        user.username = username
    if phone:
        user.phone = phone
    if image:
        try:
            user.image = image.filename
            image.save(os.path.join("app/static/images", image.filename))
        except:
            flash("Erro ao fazer upload da imagem!", category="danger")
    if newPassword:
        if newPassword == confirmNewPassword:
            user.password = newPassword
        else:
            flash("Passwords novas não coincidem!", category="danger")

    flash("Perfil atualizado com sucesso!", category="success")

    db.session.commit()
    return redirect(url_for("profile.changeProfile", id=id))
