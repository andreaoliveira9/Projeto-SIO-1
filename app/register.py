from sqlite3 import IntegrityError
from flask import Blueprint, render_template, redirect, url_for, request, flash
from flask_login import login_user
from .models import User, Cart
from . import db
import os

register = Blueprint("register", __name__)


@register.route("/register")
def regist():
    return render_template("signin.html")


@register.route("/form_signin", methods=["POST"])
def form_signin():
    nome = request.form["name"]
    email = request.form["email"]
    phone = request.form["phone"]
    user = request.form["username"]
    key = request.form["password"]
    conf_key = request.form["confirm_password"]
    profile_picture = request.files.get("image")

    if key != conf_key:
        flash("Passwords do not match!", "error")
        return redirect(url_for("register.regist"))

    if profile_picture:
        try:
            profile_picture.save(
                os.path.join("app/static/images", profile_picture.filename)
            )
            new_user = User(
                username=user,
                password=key,
                name=nome,
                email=email,
                phone=phone,
                image=profile_picture.filename,
            )
        except:
            flash("Erro ao fazer upload da imagem!", category="danger")
    else:
        print("sem imagem")
        new_user = User(
            username=user, password=key, name=nome, email=email, phone=phone
        )

    try:
        # Adicione o usuário ao banco de dados
        db.session.add(new_user)
        db.session.commit()

        new_cart = Cart(customer_id=new_user.id)
        db.session.add(new_cart)
        db.session.commit()
        login_user(new_user)
        return redirect(url_for("main.index"))
    except IntegrityError:
        db.session.rollback()
        flash("Username or email already exists!", "error")
        return redirect(url_for("register.regist"))
