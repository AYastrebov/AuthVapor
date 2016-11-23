import Vapor
import Fluent
import HTTP
import Auth
import Foundation
import Turnstile
import TurnstileWeb
import TurnstileCrypto
import VaporJWT
import Hash

struct Expiration {
    static let AccesTokenExpiration: TimeInterval = (60 * 15) // 15 Minutes later
    static let RefreshTokenExpiration: TimeInterval = (60 * 60 * 24 * 30) // 30 Days Later
}

struct Authentication {
    static let AccessTokenSigningKey: Bytes = Array("ACCESS_TOKEN_SECRET".utf8)
    static let AccesTokenValidationLength = Date() + Expiration.AccesTokenExpiration // 15 Minutes later
    static let RefreshTokenSigningKey: Bytes = Array("REFRESH_TOKEN_SECRET".utf8)
    static let RefreshTokenValidationLength = Date() + Expiration.RefreshTokenExpiration // 30 Days Later
}

final class User: BaseModel, Model {
    
    var username: String!
    var password: String!
    var accessToken: String?
    var refreshToken: String?
    
    init(credentials: UsernamePassword) {
        self.username = credentials.username
        self.password = BCrypt.hash(password: credentials.password)
        super.init()
    }
    
    init(credentials: Auth.AccessToken) {
        self.accessToken = credentials.string
        super.init()
    }
    
    override init(node: Node, in context: Context) throws {
        username = try node.extract("username")
        password = try node.extract("password")
        accessToken = try node.extract("access_token")
        refreshToken = try node.extract("refresh_token")
        try super.init(node: node, in: context)
    }
    
    override func makeNode(context: Context) throws -> Node {
        return try Node(node: [
            "id": id,
            "created_on": createdOn,
            "username": username,
            "password": password,
            "refresh_token": refreshToken,
            "access_token": accessToken,
            ])
    }
}

// MARK: Authentication
extension User: Auth.User {
    @discardableResult
    static func authenticate(credentials: Credentials) throws -> Auth.User {
        var user: User?
        
        switch credentials {
            case let credentials as UsernamePassword:
                let fetchedUser = try User.query().filter("username", credentials.username).first()
                if let password = fetchedUser?.password, password != "",
                    (try? BCrypt.verify(password: credentials.password, matchesHash: password)) == true {
                    user = fetchedUser
                }
            
            case let credentials as Identifier:
                user = try User.find(credentials.id)
            
            case let credentials as Auth.AccessToken:
                user = try User.query().filter("access_token", credentials.string).first()
            
            default:
                throw UnsupportedCredentialsError()
        }
        
        if var user = user {
            // Check if we have an accessToken first, if not, lets create a new one
            if let accessToken = user.accessToken {
                // Check if our authentication token has expired, if so, lets generate a new one as this is a fresh login
                let receivedJWT = try JWT(token: accessToken)
                
                // Validate it's time stamp
                if !receivedJWT.verifyClaims([ExpirationTimeClaim()]) {
                    try user.generateAccessToken()
                    try user.generateRefreshToken()
                }
            } else {
                // We don't have a valid access token
                try user.generateAccessToken()
                try user.generateRefreshToken()
            }
            
            try user.save()
            
            return user
        } else {
            throw IncorrectCredentialsError()
        }
    }
    
    @discardableResult
    static func register(credentials: Credentials) throws -> Auth.User {
        var newUser: User
        
        switch credentials {
            case let credentials as UsernamePassword:
                newUser = User(credentials: credentials)
            
            default:
                throw UnsupportedCredentialsError()
        }
        
        if try User.query().filter("username", newUser.username).first() == nil {
            try newUser.generateAccessToken()
            try newUser.generateRefreshToken()
            try newUser.save()
            return newUser
        } else {
            throw AccountTakenError()
        }
    }
}

// MARK: Token Generation
extension User {
    func generateAccessToken() throws {
        // Generate access Token
        let expiration = ExpirationTimeClaim(Authentication.AccesTokenValidationLength)
        let jwt = try JWT(payload: Node(expiration),
                          signer: HS256(key: Authentication.AccessTokenSigningKey))
        self.accessToken = try jwt.createToken()
    }
    
    func generateRefreshToken() throws {
        // Generate refresh Token
        let expiration = ExpirationTimeClaim(Authentication.RefreshTokenValidationLength)
        let jwt = try JWT(payload: Node(expiration),
                          signer: HS256(key: Authentication.RefreshTokenSigningKey))
        self.refreshToken = try jwt.createToken()
    }
    
    func makeTokenNode() throws -> Node {
        return try Node(node: [
            "refresh_token": refreshToken,
            "access_token": accessToken,
            "expires_in": Int(Expiration.AccesTokenExpiration)
            ])
    }
}

// MARK: Preparations
extension User: Preparation {
    static func prepare(_ database: Database) throws {
        try database.create("users") { user in
            prepare(model: user)
            user.string("username")
            user.string("password")
            user.string("refresh_token", optional: true)
            user.string("access_token", optional: true)
        }
    }
    
    static func revert(_ database: Database) throws {
        try database.delete("users")
    }
}

// MARK: Extensions

extension Array where Element : User {
    
    func publicNode() throws -> Node {
        var result: [Node] = []
        for value in self {
            try result.append(value.publicNode())
        }
        return try Node(node: result)
    }
}

extension User {
    
    func publicNode() throws -> Node {
        return try Node(node: [
            "id": id,
            "created_on": createdOn,
            "username": username
            ])
    }
    
    func merge(updates: User) {
        super.merge(updates: updates)
        username = updates.username
        password = updates.password
        accessToken = updates.accessToken
        refreshToken = updates.refreshToken
    }
}
