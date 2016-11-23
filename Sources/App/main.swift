import Auth
import Fluent
import Routing
import Vapor
import VaporPostgreSQL

let drop = Droplet()

try drop.addProvider(VaporPostgreSQL.Provider)
drop.middleware.append(AuthMiddleware(user: User.self))
drop.preparations.append(User.self)

let protect = ProtectMiddleware(error:
    Abort.custom(status: .forbidden, message: "Not authorized.")
)

let authController = AuthController()
let userController = UserController()

let api: RouteGroup  = drop.grouped("api")
let v1: RouteGroup = api.grouped("v1")
let auth: RouteGroup = v1.grouped("auth")

let secured: RouteGroup = v1.grouped(BearerAuthMiddleware(), protect)
let securedAuth: RouteGroup = auth.grouped(BearerAuthMiddleware(), protect)

api.get {
    req in try JSON(node: ["Welcome to API"])
}

v1.get {
    req in try JSON(node: ["version": "1"])
}

// /users
secured.resource("users", userController)
secured.grouped("users").get("me", handler: userController.me)

// /auth
auth.post("register", handler: authController.register)
auth.post("login", handler: authController.login)
auth.post("refresh", handler: authController.refresh)
securedAuth.post("logout", handler: authController.logout)

drop.run()
