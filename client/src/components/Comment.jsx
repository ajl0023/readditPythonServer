import React, { useEffect, useState } from "react";
import { useDispatch, useSelector } from "react-redux";
import {
  changeCommentPoint,
  newReply,
  newReplyRequest,
} from "../actions/commentActions";
import downvote, {
  ReactComponent as DownArrow,
} from "../images/down-arrow.svg";
import upvote, { ReactComponent as UpArrow } from "../images/up-arrow.svg";
const Comment = ({ comment, handleShowLogin }) => {
  const [lines, setLines] = useState([]);
  const checkDisplay = useSelector((state) => {
    return state.display.display;
  });
  const loggedIn = useSelector((state) => state.login.isLoggedIn);

  const dispatch = useDispatch();
  const [replyText, setReplyText] = useState("");
  const [replyToggle, setReplyToggle] = useState(false);
  const voteUp = () => {
    if (loggedIn) {
      dispatch(changeCommentPoint(1, comment.postid, comment.id));
    } else {
      handleShowLogin();
    }
  };
  const voteDown = () => {
    if (loggedIn) {
      dispatch(changeCommentPoint(-1, comment.postid, comment.id));
    } else {
      handleShowLogin();
    }
  };
  const handleReplyToggle = () => {
    setReplyToggle(!replyToggle);
    dispatch(newReplyRequest());
  };
  const handleReply = () => {
    let commentId = comment.id;
    dispatch(
      newReply(replyText, comment.postid, commentId, comment.master_comment)
    );
    setReplyToggle(false);
    setReplyText("");
  };
  useEffect(() => {
    let linesArr = [];
    for (let i = 0; i <= comment.depth; i++) {
      linesArr.push(
        <div
          key={comment.id + "line" + i}
          style={{
            left: i === 0 ? 0 : i * 23,
          }}
          className="thread-line-container"
        >
          <li className="thread-line"></li>
        </div>
      );
    }
    setLines(linesArr);
  }, [comment]);
  if (!comment || typeof comment.depth !== "number") {
    return null;
  }
  return (
    <div
      style={{
        position: "relative",
        paddingLeft: comment.depth === 0 ? 15 : comment.depth * 23 + 15,
        paddingTop: "10px",
      }}
    >
      {lines.map((line) => {
        return line;
      })}
      <div className="comment-vote-title-container">
        {" "}
        <div className="comment-vote-container">
          <div className="comment-vote-button-container">
            <UpArrow
              className={
                comment.voteState === 1
                  ? "comment-vote-button-color"
                  : `${
                      checkDisplay === "dark"
                        ? "dark-mode-arrow"
                        : "comment-vote-button"
                    }`
              }
              src={upvote}
              onClick={voteUp}
              alt=""
            />
            <span className={checkDisplay === "dark" ? "dark-mode-font" : ""}>
              {comment.voteTotal}
            </span>
            <DownArrow
              className={
                comment.voteState === -1
                  ? `comment-vote-button-color`
                  : `${
                      checkDisplay === "dark"
                        ? "dark-mode-arrow"
                        : "comment-vote-button"
                    }`
              }
              src={downvote}
              onClick={voteDown}
            />
          </div>
        </div>
        <div className="comment-container">
          <p
            className={`comment-author ${
              checkDisplay === "dark" ? "dark-mode-font" : ""
            }`}
          >
            {comment.author.username}
          </p>
          <div
            className={`parent-comment ${
              checkDisplay === "dark" ? "dark-mode-font" : ""
            }`}
          >
            {comment.content}
          </div>
          <div className="reply-button-container">
            {loggedIn ? (
              <button onClick={handleReplyToggle} className="reply-button">
                Reply
              </button>
            ) : null}
            {replyToggle ? (
              <div className="new-comment-container">
                <textarea
                  value={replyText}
                  onChange={(e) => {
                    setReplyText(e.target.value);
                  }}
                  placeholder="What are your thoughts?"
                  className="new-comment reply-textarea"
                  rows="6"
                ></textarea>
                <div className="submit-comment-container">
                  <button
                    onClick={handleReply}
                    className="submit-comment-button"
                  >
                    Reply
                  </button>
                </div>
              </div>
            ) : null}
          </div>
        </div>
      </div>
    </div>
  );
};
export default React.memo(Comment, (prev, next) => {
  if (prev.comment.voteState === next.comment.voteState) {
    return true;
  }
});
