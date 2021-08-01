import os
import uuid
from datetime import timedelta

import boto3
import jwt
from dotenv import load_dotenv
from flask import (Blueprint, Flask, jsonify, request, send_from_directory)
from flask.helpers import make_response
from flask_restful import Resource, abort
from flask_sqlalchemy import SQLAlchemy
from marshmallow import Schema, fields
from passlib.hash import bcrypt
from sqlalchemy import and_, func, case
from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy.inspection import inspect
from sqlalchemy.orm import (column_property, defer, deferred, relationship)
from sqlalchemy.sql.expression import desc, insert, select
from sqlalchemy.sql.schema import CheckConstraint
from waitress import serve

from utils import calcVoteDown, calcVoteUp

# logging.basicConfig()
# logging.getLogger('sqlalchemy.engine').setLevel(logging.INFO)

load_dotenv()
app = Flask(__name__, static_url_path='', static_folder='../../client/build')
my_blueprint = Blueprint(
    'my_blueprint', __name__, template_folder='templates', url_prefix='/api')


app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:123@localhost:3306/mydb'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True


db = SQLAlchemy(app)


@app.before_request
def before_request_func():
    currentUser = request.headers.get("Authorization").split(
    )[1] if request.headers.get("Authorization") else None

    if currentUser:
        userobj = jwt.decode(
            currentUser, os.environ['ACCESS_TOKEN'], algorithms=["HS256"])

        request.user = userobj

    else:
        request.user = None


def assignId():
    id = uuid.uuid4()

    return id.hex


class Comments(db.Model):

    __tablename__ = 'comments'
    id = db.Column(db.String(200), primary_key=True, default=assignId)
    depth = db.Column(db.Integer)
    parentid = db.Column(db.String(200))
    postid = db.Column(db.String(200), db.ForeignKey('posts.id'))
    post = relationship("Posts", back_populates='comments')
    main_id = db.Column(db.Integer)
    createdAt = db.Column(db.String(200), default=func.now())
    master_comment = db.Column(db.String(200), db.ForeignKey('comments.id'))
    content = db.Column(db.String(200))
    author = db.Column(db.String(200), db.ForeignKey('users.id'))
    user = relationship("Users", back_populates="comments",
                        uselist=False)


class Users(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.String(200), primary_key=True, default=assignId)
    username = db.Column(db.String(200), unique=True)
    password = deferred(db.Column(db.String(200)))
    createdAt = db.Column(db.Date, default=func.now())
    posts = relationship("Posts", back_populates='user')
    comments = relationship("Comments", back_populates='user')


class Votes(db.Model):
    __tablename__ = 'votes'

    id = db.Column(db.String(200), primary_key=True, default=assignId)
    postid = db.Column(db.String(200), db.ForeignKey('posts.id'))
    commentid = db.Column(db.String(200), db.ForeignKey('comments.id'))
    authorid = db.Column(db.String(200), db.ForeignKey('users.id'))
    score = db.Column(db.Integer)
    uid = db.Column(db.String(200))
    __table_args__ = (
        CheckConstraint('dfgzdfgzdfgg'),
    )


class Posts(db.Model):

    __tablename__ = 'posts'

    id = db.Column(db.String(200), primary_key=True, default=assignId)

    main_id = db.Column(db.Integer)
    image = db.Column(db.String(200))
    title = db.Column(db.String(200))
    createdAt = db.Column(db.String(200), default=func.now())

    content = db.Column(db.String(200))
    hotScore = db.Column(db.Float)
    author_id = db.Column(db.String(200), db.ForeignKey('users.id'))
    user = relationship("Users", back_populates="posts",
                        uselist=False, lazy=False)
    comments = relationship(
        "Comments", back_populates='post', uselist=True)

    @hybrid_property
    def test(self):
        return


class UserSchema(Schema):
    id = fields.Str()

    username = fields.Str()


class CommentsSchema(Schema):

    createdAt = fields.Str()

    createdAt = fields.Str()
    content = fields.Str()

    id = fields.Str()
    depth = fields.Int()
    main_id = fields.Str()
    postid = fields.Str()
    master_comment = fields.Str()
    parentid = fields.Str()
    voteTotal = fields.Int()
    voteState = fields.Int()
    rank = fields.Int()
    user = fields.Nested(UserSchema, data_key='author')


class PostSchema(Schema):

    image = fields.Str()
    createdAt = fields.Str()
    title = fields.Str()
    createdAt = fields.Str()
    content = fields.Str()
    hotScore = fields.Float()
    id = fields.Str()
    comments = fields.Nested(CommentsSchema, many=True)
    main_id = fields.Int()

    voteTotal = fields.Int()
    voteState = fields.Int()
    user = fields.Nested(UserSchema, data_key='author')


def addVoteState(model):

    inspect(model).add_property('voteState',
                                column_property(func.ifnull(select(Votes.score).where(
                                    and_(Votes.authorid == request.user.get('id'), getattr(Votes, "postid" if model == Posts else 'commentid') == model.id)).as_scalar(), 0)))


def addVoteTotal(id, model):

    inspect(model).add_property('voteTotal',
                                column_property(
                                    func.ifnull(select(func.ifnull(func.sum(Votes.score), 0)).where(
                                        getattr(Votes, "postid" if model == Posts else 'commentid') == (model.id if not id else id)).as_scalar(), 0)))


@ app.route('/', methods=['GET'])
def sendClient():
    return send_from_directory(app.static_folder, 'index.html')


@ my_blueprint.route('/me', methods=['GET'])
def user_info():
    schema = UserSchema()
    user = request.user

    if user is False:
        abort(403)
    users_data = Users.query.filter_by(id=user.get("id")).one()
    formatted = schema.dump(users_data)
    return jsonify(formatted)


@ my_blueprint.route('/posts', methods=['GET'], defaults={'sort': None})
@ my_blueprint.route('/posts/sort/<sort>', methods=['GET'])
def posts(sort):

    user = request.user.get("id") if request.user else None

    schema = PostSchema(exclude=['comments'])
    if user:
        addVoteState(Posts)
    else:
        inspect(Posts).add_property('voteState',
                                    column_property(select(0)))

    addVoteTotal(None, Posts)
    result = db.session.query(
        Posts
    )

    if sort == 'new':
        result = result.order_by(desc(Posts.createdAt))
    if sort == 'top':
        result = result.order_by(desc(Posts.voteTotal))
    if sort == 'hot':
        result = result.order_by(desc(Posts.hotScore))

    resultList = result.all()
    inspect(resultList[0])

    formatted = schema.dump(resultList, many=True)

    return jsonify(formatted)


@ my_blueprint.route('/posts/<id>', methods=['GET'])
def singlePost(id):

    user = request.user.get("id") if request.user else None

    schema = PostSchema(exclude=['comments'])

    if user:
        addVoteState(Posts)
    addVoteTotal(None, Posts)
    post = Posts.query.filter_by(id=id).scalar()

    formatted = schema.dump(post)
    return jsonify(formatted)


@ my_blueprint.route('/posts/<id>', methods=['DELETE'])
def deletePost(id):
    user = request.user.get("id") if request.user else None
    post = Posts.query.where(Posts.id == id, Posts.author_id == user).first()

    db.session.delete(post)
    db.session.commit()
    return jsonify('deleted')


def editPost(id):
    user = request.user.get("id") if request.user else None
    post = Posts.query.where(Posts.id == id).update(
        dict(content=case((Posts.author_id == user, request.get_json().get('content')))))
    print(post, 234234234)
    db.session.commit()

    return jsonify(post)


@ my_blueprint.route('/posts', methods=['Post'])
def createPost():
    s3 = boto3.resource('s3',  aws_access_key_id=os.environ.get("AWS_ACCESS"),
                        aws_secret_access_key=os.environ.get("AWS_SECRET"))

    user = request.user

    schema = PostSchema()

    if user is False:
        abort(403)
    post = Posts(title=request.form.get('title'), content=request.form.get('content'),
                 author_id=user.get('id'), image=request.form.get('image'), hotScore=func.log10(1) * 86400 / .301029995663981 + func.UNIX_TIMESTAMP(Posts.createdAt))

    db.session.add(post)

    db.session.flush()
    vote = Votes(postid=post.id, authorid=user.get(
        'id'), score=1, uid=func.concat(post.id, user.get('id')))

    db.session.add(vote)
    formatted = schema.dump(post)
    db.session.commit()
    formatted['voteState'] = 1
    formatted['voteTotal'] = 1
    return make_response(formatted)


@ my_blueprint.route('/login', methods=['Post'])
def login():
    data = request.get_json(force=True)

    username = data['username']
    password = data['password']
    user = db.session.query(Users).filter(Users.username == username).scalar()
    hash = user.password

    if bcrypt.verify(password, hash) is False:

        abort(422)

    refresh_token = jwt.encode(
        {"id": user.id, "username": username}, os.environ['REFRESH_TOKEN'])
    access_token = jwt.encode(
        {"id": user.id, "username": username}, os.environ['ACCESS_TOKEN'])
    resp = make_response({"jwt_token": access_token,
                          'username': username, 'id': user.id})
    resp.set_cookie('refresh_token', value=refresh_token,
                    max_age=timedelta(milliseconds=365 * 24 * 60 * 60 * 1000), domain="127.0.0.1:5000")

    return resp


@ my_blueprint.route('/logout', methods=['Post'])
def logout():
    resp = make_response("user logged out")
    resp.delete_cookie(key='refresh_token')
    return resp


@ my_blueprint.route('/signup', methods=['Post'])
def signup():
    data = request.get_json(force=True)

    username = data['username']
    password = data['password']

    hash = bcrypt.hash(password)
    stmt = (insert(Users).values(username=username,
                                 password=hash, ))
    db.session.execute(stmt)
    db.session.commit()
    resp = make_response()

    return resp


@ my_blueprint.route('/comments/<id>', methods=['GET'])
def comments(id):

    schema = CommentsSchema()
    # if bool(request.user) is False:
    #     abort(403)

    # request.user
    user = request.user
    inspect(Comments).add_property('rank',
                                   column_property(func.dense_rank().over(
                                       order_by=Comments.depth).label('test')))
    if user:
        addVoteState(Comments)
    addVoteTotal(None, Comments)

    x = db.session.query(Comments).filter(Comments.postid == id).all()

    # comments = Comments.query.filter_by(postid=id,).all()
    formatted = jsonify(schema.dump(x, many=True))
    return make_response(formatted)


@ my_blueprint.route('/comments/<id>', methods=['POST'])
def postComment(id):

    user = request.user

    schema = CommentsSchema()

    if user is False:
        abort(403)
    comment = Comments(content=request.get_json().get('content'),
                       author=user.get('id'), postid=id, depth=0, master_comment=request.get_json().get("master_comment"), parentid=request.get_json().get("parentid"))

    db.session.add(comment)
    db.session.flush()

    vote = Votes(commentid=comment.id, authorid=user.get(
        'id'), score=1, uid=func.concat(comment.id, user.get('id')))

    db.session.add(vote)
    db.session.commit()
    formatted = schema.dump(comment)
    formatted['voteState'] = 1
    formatted['voteTotal'] = 1
    return make_response(formatted)


@ my_blueprint.route('/comments/<postid>/<commentid>', methods=['POST'])
def postreply(postid, commentid):

    user = request.user

    schema = CommentsSchema()
    if user is False:
        abort(403)
    calcDepth = Comments.query.filter_by(id=commentid).first()

    comment = Comments(content=request.get_json().get('content'),
                       author=user.get('id'), postid=postid, depth=calcDepth.depth+1, master_comment=request.get_json().get("master_comment"), parentid=commentid)

    db.session.add(comment)
    db.session.flush()
    vote = Votes(commentid=comment.id, authorid=user.get(
        'id'), score=1, uid=func.concat(comment.id, user.get('id')))
    db.session.add(vote)
    db.session.commit()

    formatted = schema.dump(comment)
    formatted['voteState'] = 1
    formatted['voteTotal'] = 1
    return make_response(formatted)


@ my_blueprint.route('/voteup/<id>', methods=['PUT'])
def voteup(id):

    user = request.user
    if user is False:
        abort(403)

    voteType = request.get_json().get('type')

    query = calcVoteUp(voteType, id, Posts, Votes, request.user.get('id'))

    db.session.execute(query)

    if voteType == 'postid':
        addVoteTotal(id, Posts)
        Posts.query.where(Posts.id == id).update(dict(hotScore=func.log10(
            Posts.voteTotal+1) * func.sign(Posts.voteTotal) * 86400 / .301029995663981 + func.UNIX_TIMESTAMP(Posts.createdAt)))
    db.session.commit()

    return jsonify()


@ my_blueprint.route('/votedown/<id>', methods=['PUT'])
def votedown(id):

    user = request.user
    if user is False:
        abort(403)
    voteType = request.get_json().get('type')

    query = calcVoteDown(voteType, id, Posts, Votes, request.user.get('id'))

    db.session.execute(query)

    if voteType == 'postid':
        addVoteTotal(id, Posts)
        Posts.query.where(Posts.id == id).update(dict(hotScore=func.log10(
            func.abs(Posts.voteTotal)+1) * func.sign(Posts.voteTotal) * 86400 / .301029995663981 + func.UNIX_TIMESTAMP(Posts.createdAt)))
    db.session.commit()

    return jsonify()


app.register_blueprint(my_blueprint)
print(50)
if __name__ == "__main__":

    serve(app, listen='*:8080')
