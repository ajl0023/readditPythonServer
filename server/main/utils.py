from sqlalchemy import and_, create_engine, func
from sqlalchemy import case


def calcVoteUp(type, id, Posts, Votes, userid):

    inserted = Votes.__table__.insert().prefix_with('IGNORE').values(
        **{type: id}, authorid=userid, score=1, uid=id+userid)

    Votes.query.where(
        and_(getattr(Votes, type) == id, Votes.authorid == userid)).update(dict(score=case(
            (Votes.score == 1, 0),
            (Votes.score == -1, 1),
            (Votes.score == 0, 1)
        )))
    return inserted

    # print(vote, 443434)
    # if type == 'postid':
    #     Posts.query.


def calcVoteDown(type, id, Posts, Votes, userid):

    inserted = Votes.__table__.insert().prefix_with('IGNORE').values(
        **{type: id}, authorid=userid, score=-1, uid=id+userid)

    Votes.query.where(
        and_(getattr(Votes, type) == id, Votes.authorid == userid)).update(dict(score=case(
            (Votes.score == 1, -1),
            (Votes.score == -1, 0),
            (Votes.score == 0, -1)
        )))
    return inserted
