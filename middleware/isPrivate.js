module.exports = (req, res, next) => {
    if (req.session.currentUser.isPrivate) {
      next();
    } else {
      res.redirect("/user/private");
    }
  };