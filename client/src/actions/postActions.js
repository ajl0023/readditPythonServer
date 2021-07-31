import axios from "axios";
import "cross-fetch/polyfill";
import { normalize } from "normalizr";
import { post, comment } from "../schemas";
import {
  DELETE_POST,
  EDIT_POST,
  NEW_POST_REQUEST,
  NEW_POST_SUCCESS,
  NEXT_PAGE,
  POST_CREATION_CHANGE_SUBMISSION_TYPE,
  PREV_PAGE,
  RECEIVE_COMMENTS,
  RECEIVE_POSTS,
  RECEIVE_SINGLE_POSTS,
  REQUEST_COMMENTS,
  REQUEST_POSTS,
  REQUEST_SINGLE_POST,
  RESET_POST,
  SET_POST,
  SET_POST_MODAL,
  SORT_POSTS,
  VOTE_CAST,
} from "../types";
import { fetchComments } from "./commentActions";

function requestPosts(e) {
  return {
    type: REQUEST_POSTS,
  };
}
function submitPostSuccess(post) {
  let id = post.id;
  post["newPost"] = true;
  return (dispatch) => {
    dispatch({ type: NEW_POST_SUCCESS, post, id });
  };
}
export function newPostSubmissionType(postType) {
  return (dispatch) => {
    dispatch({ type: POST_CREATION_CHANGE_SUBMISSION_TYPE, postType });
  };
}
export function changePostSubmissionType(postType) {
  return (dispatch, getState) => {
    let currentValue = getState().changeNewSubmissionType.submissionType;
    if (postType === currentValue) {
      return;
    } else {
      dispatch({
        type: POST_CREATION_CHANGE_SUBMISSION_TYPE,
        postType,
      });
    }
  };
}
export function changePoint(point, postId, voteState) {
  return (dispatch, getState) => {
    dispatch({
      type: VOTE_CAST,
      postId,
      point,
      currentVoteState: voteState,
    });
    if (point === 1) {
      return axios({
        url: `/api/voteup/${postId}`,
        method: "PUT",
        data: {
          type: "postid",
        },
        withCredentials: true,
      });
    }
    if (point === -1) {
      return axios({
        url: `/api/votedown/${postId}`,
        method: "PUT",
        data: {
          type: "postid",
        },
        withCredentials: true,
      });
    }
  };
}
export function setPostModal(post) {
  return {
    type: SET_POST_MODAL,
    post,
  };
}
export function submitPostAttempt() {
  return {
    type: NEW_POST_REQUEST,
  };
}
export function submitPost(form) {
  return (dispatch) => {
    return axios({
      url: `/api/posts`,
      method: "POST",
      data: form,
      withCredentials: true,
    }).then((res) => {
      if (res.status === 200) {
        dispatch(submitPostSuccess(res.data));
      }
    });
  };
}
function requestSinglePost() {
  return {
    type: REQUEST_SINGLE_POST,
  };
}
export function reset() {
  return {
    type: RESET_POST,
  };
}
function getNormalizeData(myData, params, type) {
  const normalizedData = normalize(myData, [type === "posts" ? post : comment]);
  return normalizedData;
}
export function sortPosts() {}
export function deletePost(postId, params) {
  return (dispatch) => {
    dispatch({
      type: DELETE_POST,
      postId,
      params: params ? params : "default",
    });
    return axios({
      url: `/api/posts/${postId}`,
      method: "DELETE",
      withCredentials: true,
    });
  };
}
export function editPost(postId, content) {
  return (dispatch) => {
    dispatch({ type: EDIT_POST, postId, content });
    return axios({
      url: `/api/posts/${postId}`,
      method: "PUT",
      withCredentials: true,
      data: {
        content: content,
      },
    });
  };
}

export function fetchPosts(query, id, params, e) {
  return (dispatch) => {
    dispatch(requestPosts(e));
    return axios
      .get(
        `/api/posts${params && params.sort ? `/sort/${params.sort}` : ""}${
          query ? `?${query}=${id}` : ""
        }`,
        {
          withCredentials: true,
        }
      )
      .then((res) => {
        const normalizedData = getNormalizeData(res.data, params, "posts");
        dispatch({
          type:
            params && params.sort && e === "click" ? SORT_POSTS : RECEIVE_POSTS,
          normalizedData,
          offset: res.data.offset,
          sort: params && params.sort ? params.sort : "default",
        });
        return res.data;
      });
  };
}
export function prevPage(id, params) {
  return (dispatch) => {
    dispatch(requestPosts());
    return new Promise((resolve) => {
      axios({
        url: `/api/posts/${
          params.length > 0 ? params : ""
        }?page[size]=${10}&before=${id}`,
        method: "GET",
        withCredentials: true,
      }).then((res) => {
        if (res.status === 200) {
          const normalizedData = getNormalizeData(
            { posts: res.data.posts },
            params
          );
          dispatch({
            type: PREV_PAGE,
            normalizedData,
            offset: res.data.offset,
            sort: params.sort ? params.sort : "default",
          });
          resolve("completed");
        }
      });
    });
  };
}
export function nextPage(id, params) {
  return (dispatch) => {
    dispatch(requestPosts());
    return new Promise((resolve) => {
      axios({
        url: `/api/posts/${
          params && params.sort ? params.sort : ""
        }?page[size]=${10}&after=${id}`,
        method: "GET",
        withCredentials: true,
      }).then((res) => {
        if (res.status === 200) {
          const normalizedData = getNormalizeData(
            { posts: res.data.posts },
            params
          );
          dispatch({
            type: NEXT_PAGE,
            normalizedData,
            offset: res.data.offset,
            sort: params.sort ? params.sort : "default",
          });
          resolve("completed");
        }
      });
    });
  };
}
export function setPostRange(before, after) {
  return { type: SET_POST, before, after };
}
export function fetchSinglePost(id) {
  return (dispatch) => {
    dispatch(requestSinglePost());

    const posts = axios({
      url: `/api/posts/${id}`,
      method: "GET",
      withCredentials: true,
    }).then((data) => {
      return {
        posts: data.data,
      };
    });

    const comments = dispatch(fetchComments(id));
    return Promise.all([posts, comments]).then((res) => {
      const promises = {};

      for (let data of res) {
        const key = Object.keys(data)[0];

        promises[key] = data;
      }

      const normalizedData = getNormalizeData(promises.posts, null, "posts");

      dispatch({ normalizedData, type: RECEIVE_SINGLE_POSTS });

      const comments = promises.comments;

      const normalizedComments = getNormalizeData(
        comments.comments,
        null,
        "comments"
      );

      dispatch({
        type: RECEIVE_COMMENTS,
        comments: normalizedComments.entities.comments,
        commentids: normalizedComments.result,
        postid: id,
      });

      return res;
    });
  };
}
