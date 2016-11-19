import Auth
import Fluent
import Routing
import Vapor
import VaporPostgreSQL

let drop = Droplet()

try drop.addProvider(VaporPostgreSQL.Provider)
drop.addConfigurable(middleware: AuthMiddleware(user: User.self), name: "auth")
drop.preparations = [User.self]

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

// auth
v1.post("register", handler: authController.register)
v1.post("login", handler: authController.login)
v1.post("logout", handler: authController.logout)

drop.run()
