const catchAsync = require("../utils/catchAsync");
exports.addUserIdToQuery = catchAsync(async (req, res, next) => {
  req.query.participants = req.user._id.toString();
  next();
});
