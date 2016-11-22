import Auth
import Fluent
import Routing
import Vapor
import VaporPostgreSQL

let drop = Droplet()
let auth = AuthMiddleware(user: User.self)

try drop.addProvider(VaporPostgreSQL.Provider)
drop.middleware.append(auth)
drop.preparations.append(User.self)

let protect = ProtectMiddleware(error:
    Abort.custom(status: .forbidden, message: "Not authorized.")
)

let authController = AuthController()
let userController = UserController()

let api: RouteGroup  = drop.grouped("api")
let v1: RouteGroup = api.grouped("v1")

let secured: RouteGroup = v1.grouped(BearerAuthMiddleware(), protect)

api.get {
    req in try JSON(node: ["Welcome to API"])
}

v1.get {
    req in try JSON(node: ["version": "1"])
}

// /users
secured.resource("users", userController)
secured.grouped("users").get("me", handler: userController.me)

// auth
v1.post("register", handler: authController.register)
v1.post("login", handler: authController.login)
v1.post("refresh", handler: authController.refresh)
secured.post("logout", handler: authController.logout)
secured.post("validate", handler: authController.validateAccessToken)

drop.run()
