import axios from "axios";
import { normalize } from "normalizr";
import { comment } from "../schemas";
import {
  NEW_COMMENT_REQUEST,
  NEW_COMMENT_SUCCESS,
  NEW_REPLY_REQUEST,
  NEW_REPLY_SUCCESS,
  REQUEST_COMMENTS,
  VOTE_CAST,
} from "../types";

export function newCommentRequest() {
  return {
    type: NEW_COMMENT_REQUEST,
  };
}
function getNormalizeData(myData, params) {
  const normalizedData = normalize(myData, [comment]);

  return normalizedData;
}
function newCommentSuccess(savedComment, postId, parentId) {
  return (dispatch, getState) => {
    dispatch({
      type: NEW_COMMENT_SUCCESS,
      savedComment,
      postId,
      parentId,
    });
  };
}
export function newComment(content, postId) {
  return (dispatch, getState) => {
    dispatch(newCommentRequest());
    return axios({
      url: `/api/comments/${postId}`,
      method: "POST",
      data: {
        content,
        postid: postId,
      },
      withCredentials: true,
    }).then((res) => {
      dispatch(newCommentSuccess(res.data, postId));
    });
  };
}

export function fetchComments(postid) {
  return (dispatch) => {
    dispatch({
      type: REQUEST_COMMENTS,
    });
    return axios({
      url: `/api/comments/${postid}`,
      method: "GET",

      withCredentials: true,
    }).then((data) => {
      return {
        comments: data.data,
      };
    });
  };
}
export function newReplyRequest() {
  return {
    type: NEW_REPLY_REQUEST,
    test: {},
  };
}
export function test(test) {
  return (dispatch, getState) => {
    dispatch(test.push("sdfsdf"));
  };
}
export function changeCommentPoint(point, postId, commentId) {
  return (dispatch, getState) => {
    const currentCommentId = commentId;
    const currentComment = getState().comments.byId[currentCommentId];
    const currentVoteState = currentComment.voteState;
    dispatch({
      type: VOTE_CAST,
      point,
      commentId,
      currentVoteState,
    });
    if (point === 1) {
      axios({
        url: `/api/voteup/${commentId}`,
        method: "PUT",
        data: {
          type: "commentid",
        },
        withCredentials: true,
      });
    } else if (point === -1) {
      axios({
        url: `/api/votedown/${commentId}`,
        method: "PUT",
        data: {
          type: "commentid",
        },
        withCredentials: true,
      });
    }
  };
}
export function newReply(content, postId, commentId, master_comment) {
  return (dispatch, getState) => {
    const post = getState().posts.byId[postId];
    const parentIndex = post.comments.findIndex((comment) => {
      return comment === commentId;
    });

    axios({
      url: `/api/comments/${postId}/${commentId}`,
      method: "POST",
      data: {
        content,
        master_comment: master_comment || commentId,
        postid: postId,
        parentid: commentId,
      },
      withCredentials: true,
    }).then((res) => {
      dispatch({
        type: NEW_REPLY_SUCCESS,
        reply: res.data,
        parentIndex,
        postId,
        commentId,
      });
    });
  };
}
