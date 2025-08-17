<?php

namespace App\Http\Controllers\auth;

use App\Models\User;
use App\Mail\WelcomeMail;
use Illuminate\Http\Request;
use App\Http\Controllers\Controller;
use Illuminate\Support\Facades\Hash;

class AuthController extends Controller
{
    public function login(Request $request)
    {
        if (auth()->check()) {
        return response()->json([
            'message' => 'Vous êtes déjà connecté.'
        ], 400);
    }

        $credentials = $request->only('email', 'password');
        if (!auth()->attempt($credentials)) {
            return response()->json([
                'message' => 'Identifiants invalides'
            ], 401);
        }
        $user = auth()->user();
        $token = $user->createToken('auth_token')->plainTextToken;
        return response()->json([
            'message' => 'Connexion réussie',
            'user' => $user,
            'token' => $token
        ], 200);
    }

    public function logout()
    {
        $user = auth()->user();
        if (!$user) {
            return response()->json([
                'message' => 'Utilisateur non trouvé'
            ], 404);
        }
        $user->tokens()->delete();
        return response()->json([
            'message' => 'Déconnexion réussie'
        ], 200);
    }
    public function register(Request $request)
    {
        $validatedData = $request->validate([
            'name' => 'required|string|max:255',
            'email' => 'required|string|email|max:255|unique:users',
            'password' => 'required|string|min:8',
        ]);

        $validatedData['password'] = Hash::make($validatedData['password']);

        $user = User::create($validatedData);

        //Mail::to($user->email)->send(new WelcomeMail($user));


        return response()->json([
            'message' => 'Inscription réussie',
            'user' => $user
        ], 201);
    }
    public function userProfile()
    {
        $user = auth()->user();

        if (!$user) {
            return response()->json([
                'message' => 'Utilisateur non trouvé'
            ], 404);
        }

        return response()->json([
            'user' => $user
        ], 200);
    }
    public function updateProfile(Request $request)
    {
        $user = auth()->user();

        if (!$user) {
            return response()->json([
                'message' => 'Utilisateur non trouvé'
            ], 404);
        }

        $validatedData = $request->validate([
            'name' => 'sometimes|string|max:255',
            'email' => 'sometimes|string|email|max:255|unique:users,email,' . $user->id,
            'password' => 'sometimes|string|min:8|confirmed',
        ]);

        if (isset($validatedData['password'])) {
            $validatedData['password'] = bcrypt($validatedData['password']);
        }

        $user->update($validatedData);

        return response()->json([
            'message' => 'Profil mis à jour avec succès',
            'user' => $user
        ], 200);
    }
    public function deleteProfile()
    {
        $user = auth()->user();

        if (!$user) {
            return response()->json([
                'message' => 'Utilisateur non trouvé'
            ], 404);
        }

        $user->delete();

        return response()->json([
            'message' => 'Profil supprimé avec succès'
        ], 200);
    }
    public function getAllUsers()
    {
        $users = User::all();

        if ($users->isEmpty()) {
            return response()->json([
                'message' => 'Aucun utilisateur trouvé'
            ], 404);
        }

        return response()->json([
            'data' => $users
        ], 200);
    }

    public function updateUserRole(Request $request, $id)
    {
        $user = User::find($id);

        if (!$user) {
            return response()->json([
                'message' => 'Utilisateur non trouvé'
            ], 404);
        }

        $validatedData = $request->validate([
            'role' => 'required|string|in:admin,teacher,parent,student',
        ]);

        $user->role = $validatedData['role'];
        $user->save();

        return response()->json([
            'message' => 'Rôle mis à jour avec succès',
            'user' => $user
        ], 200);
    }
}
