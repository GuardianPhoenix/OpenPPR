from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user

app = Flask(__name__)
app.config['SECRET_KEY'] = '98a5da902074b8aeda4d1c0135220430f4c07681e58cff621434098bf8b64944'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///openppr.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Models
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    is_default_password = db.Column(db.Boolean, default=True)  # Nouveau champ
    created_at = db.Column(db.DateTime, default=db.func.now())

class Project(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    name = db.Column(db.String(150), nullable=False)
    company_name = db.Column(db.String(150), nullable=False)
    created_at = db.Column(db.DateTime, default=db.func.now())

class ChecklistItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.Integer, db.ForeignKey('project.id'), nullable=False)
    item_text = db.Column(db.String(300), nullable=False)
    is_completed = db.Column(db.Boolean, default=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Routes
@app.route('/')
def home():
    return redirect(url_for('login'))



@app.route('/changepassword', methods=['GET', 'POST'])
@login_required
def changepassword():
    if request.method == 'POST':
        old_password = request.form.get('old_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        if not old_password or not new_password or not confirm_password:
            flash('Tous les champs sont obligatoires.', 'danger')
            return redirect(url_for('changepassword'))

        if not bcrypt.check_password_hash(current_user.password, old_password):
            flash('Ancien mot de passe incorrect.', 'danger')
            return redirect(url_for('changepassword'))

        if new_password != confirm_password:
            flash('Les nouveaux mots de passe ne correspondent pas.', 'danger')
            return redirect(url_for('changepassword'))

        # Mise à jour du mot de passe
        hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
        current_user.password = hashed_password
        current_user.is_default_password = False  # Marque le mot de passe comme non par défaut
        db.session.commit()

        flash('Mot de passe mis à jour avec succès.', 'success')
        return redirect(url_for('dashboard'))

    return render_template('changepassword.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        user = User.query.filter_by(username=username).first()

        if not user or not bcrypt.check_password_hash(user.password, password):
            flash('Login ou mot de passe incorrect.', 'danger')
            return redirect(url_for('login'))

        login_user(user)
        flash('Connexion réussie !', 'success')
        return redirect(url_for('dashboard'))

    return render_template('login.html')

@app.route('/dashboard')
@login_required
def dashboard():
    projects = Project.query.filter_by(user_id=current_user.id).all()
    return render_template('dashboard.html', projects=projects)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Déconnecté avec succès.', 'info')
    return redirect(url_for('login'))


@app.route('/projects', methods=['GET', 'POST'])
@login_required
def projects():
    if request.method == 'POST':
        # Récupérer les données du formulaire
        name = request.form.get('name')
        company_name = request.form.get('company_name')

        if not name or not company_name:
            flash("Tous les champs sont obligatoires.", "danger")
            return redirect(url_for('projects'))

        # Créer un nouveau projet
        new_project = Project(
            user_id=current_user.id,
            name=name,
            company_name=company_name
        )
        db.session.add(new_project)
        db.session.commit()
        flash("Projet ajouté avec succès !", "success")
        return redirect(url_for('projects'))

    # Récupérer les projets existants pour l'utilisateur connecté
    user_projects = Project.query.filter_by(user_id=current_user.id).all()
    return render_template('projects.html', projects=user_projects)


# Initialisation de la base de données
with app.app_context():
    db.create_all()

    # Vérification ou création de l'administrateur par défaut
    admin_user = User.query.filter_by(username='admin').first()
    if not admin_user:
        default_password = bcrypt.generate_password_hash('admin').decode('utf-8')
        admin_user = User(
            username='admin',
            email='admin@example.com',
            password=default_password,
            is_default_password=True  # Marque le mot de passe comme par défaut
        )
        db.session.add(admin_user)
        db.session.commit()
        print("Compte administrateur créé : Nom d'utilisateur = 'admin', Mot de passe = 'admin'")
    else:
        print("L'utilisateur admin existe déjà.")

if __name__ == '__main__':
    app.run(debug=True)
