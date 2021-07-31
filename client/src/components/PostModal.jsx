import React, { useState, useEffect } from "react";
import { connect, useDispatch, useSelector } from "react-redux";
import { useHistory, useParams } from "react-router-dom";
import { fetchComments, newComment } from "../actions/commentActions";
import { changePoint, editPost } from "../actions/postActions";
import downvote, {
  ReactComponent as DownArrow,
} from "../images/down-arrow.svg";
import { ReactComponent as Edit } from "../images/edit.svg";
import upvote, { ReactComponent as UpArrow } from "../images/up-arrow.svg";
import Comment from "./Comment";
import { createSelector } from "reselect";

const PostModal = (props) => {
  let currentPost = props.post;
  const params = useParams();
  const dispatch = useDispatch();
  const history = useHistory();
  const [commentText, setCommentText] = useState("");
  const [edit, setEdit] = useState(false);
  const [editText, setEditText] = useState("");

  const currentUser = useSelector((state) => state.currentUser.id);
  const comments = useSelector((state) => {
    return state.comments.byId;
  });
  const commentids = useSelector((state) => {
    if (currentPost) {
      return state.posts.byId[currentPost.id].comments;
    }
  });

  const loggedIn = useSelector((state) => state.login.isLoggedIn);

  const back = (e) => {
    e.stopPropagation();
  };
  const handleReroute = () => {
    history.push("/");
  };
  const handleSubmitComment = () => {
    dispatch(newComment(commentText, props.post.id));
    setCommentText("");
  };
  const handleUpvote = () => {
    if (loggedIn) {
      dispatch(changePoint(1, props.post.id, props.post.voteState));
    } else {
      props.handleShowLogin();
    }
  };
  const checkDisplay = useSelector((state) => {
    return state.display.display;
  });
  const handleDownVote = () => {
    if (loggedIn) {
      dispatch(changePoint(-1, props.post.id, props.post.voteState));
    } else {
      props.handleShowLogin();
    }
  };
  const handleEdit = () => {
    setEdit(true);
  };
  const handleCancelEdit = () => {
    setEdit(false);
  };
  const saveEdit = (id) => {
    dispatch(editPost(id, editText));
    setEdit(false);
  };
  if (!currentPost || !comments || !commentids) {
    return <div></div>;
  }
  const date = new Date(currentPost.createdAt);
  const formatDate = new Intl.DateTimeFormat("en-US", {}).format(date);
  const commentsArr = [];
  const findAllComments = (currentComments) => {
    return currentComments;
  };

  const postComments =
    commentids.length === 0
      ? []
      : commentids.map((id) => {
          return comments[id];
        });

  if (postComments.length > 0) {
    findAllComments(postComments);
  }
  return (
    <div
      onClick={handleReroute}
      className={`modal-wrapper ${checkDisplay === "dark" ? "dark-mode" : ""}`}
    >
      <input type="checkbox" id="trigger" className={"burger-input"} />
      <label
        htmlFor="trigger"
        className={`close-label ${
          checkDisplay === "dark" ? "dark-mode-burger" : ""
        }`}
      >
        <div onClick={handleReroute} className={"main-close-icon-container"}>
          <span className={"main-close-icon"}></span>
        </div>
      </label>
      <div
        onClick={back}
        className={`card-modal ${
          checkDisplay === "dark" ? "dark-mode-border" : ""
        }`}
      >
        <>
          <p className="card-modal-author">
            {" "}
            u/{currentPost.author ? currentPost.author.username : "deleted"}
          </p>
          <p
            className={`modal-date ${
              checkDisplay === "dark" ? "dark-mode-font" : ""
            }`}
          >
            {formatDate}
          </p>{" "}
          <h4
            className={`card-modal-title ${
              checkDisplay === "dark" ? "dark-mode-font" : ""
            }`}
          >
            {currentPost.title}
          </h4>
        </>
        <>
          {currentPost.author && currentUser === currentPost.author.id ? (
            <div className="edit-container">
              <p className={`card-modal-content ${edit ? "inactive" : null} `}>
                {currentPost.content}
              </p>
              <textarea
                onChange={(e) => {
                  setEditText(e.target.value);
                }}
                className={edit ? "edit-text-area" : "inactive"}
                value={editText}
              ></textarea>
              <div className={edit ? `edit-button-container` : `inactive`}>
                <button
                  onClick={() => saveEdit(currentPost.id)}
                  className="edit-submit-button"
                >
                  Save
                </button>
                <button
                  onClick={handleCancelEdit}
                  className="edit-cancel-button"
                >
                  Cancel
                </button>
              </div>
              <button
                className={`edit-button ${edit ? "inactive" : null}`}
                onClick={handleEdit}
              >
                <Edit />
              </button>
            </div>
          ) : null}
          <div className="post-image-container">
            <img className="post-image" src={props.post.image} alt="" />
          </div>
          {currentUser ? (
            <div className="new-comment-container">
              <textarea
                className="new-comment"
                name=""
                id=""
                placeholder="What are your thoughts?"
                rows="6"
                value={commentText}
                onChange={(e) => setCommentText(e.target.value)}
              ></textarea>
              <span className="submit-comment-container">
                <button
                  onClick={() => {
                    handleSubmitComment();
                  }}
                  className="submit-comment-button"
                >
                  Comment
                </button>
              </span>
            </div>
          ) : (
            <div
              className={`no-user-comment-container ${
                checkDisplay === "dark" ? "dark-mode-border" : ""
              } `}
            >
              <p className="no-user-comment">
                Log in or sign up to leave a comment
              </p>
              <div className="auth-button-container">
                <button
                  className={checkDisplay === "dark" ? "dark-mode" : ""}
                  onClick={props.handleShowLogin}
                >
                  log in
                </button>
                <button onClick={props.handleShowSignup}>sign up</button>
              </div>
            </div>
          )}
          <div className="card-modal-vote-container">
            <li onClick={handleUpvote}>
              <UpArrow
                className={
                  currentPost.voteState === 1
                    ? `vote-button-color`
                    : `${
                        checkDisplay === "dark"
                          ? "dark-mode-arrow"
                          : "vote-button"
                      }`
                }
                src={upvote}
                alt=""
              />
            </li>
            <li className={checkDisplay === "dark" ? "dark-mode-font" : ""}>
              {currentPost.voteTotal}
            </li>
            <li onClick={handleDownVote}>
              <DownArrow
                className={
                  currentPost.voteState === -1
                    ? `vote-button-color`
                    : `${
                        checkDisplay === "dark"
                          ? "dark-mode-arrow"
                          : "vote-button"
                      }`
                }
                src={downvote}
                alt=""
              />
            </li>
          </div>
          <h4
            className={`comment-section-header ${
              checkDisplay === "dark" ? "dark-mode-font" : ""
            } `}
          >
            Comments
          </h4>
          <div className="main-comment-container">
            {postComments.map((comment) => {
              return (
                <Comment
                  allComments={comments}
                  handleShowLogin={props.handleShowLogin}
                  key={comment.id}
                  comment={comment}
                />
              );
            })}
          </div>
        </>
      </div>
    </div>
  );
};
function mapStateToProps(state, ownProps) {
  let id = ownProps.match.params.id;
  let post;
  post = state.posts.byId[id];
  return {
    post: post,
  };
}
export default connect(mapStateToProps)(PostModal);
