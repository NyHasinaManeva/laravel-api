<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Auth\Events\Validated;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;

class AuthController extends Controller
{
    public function register(Request $request){
        // $validated = $request->validate([
        //     'name'=>'required|string|max:255',
        //     'email'=>'required|string|max:255|unique:users|email',
        //     'password'=>'required|string|max:6|confirmed',
        // ]);
        $validated = Validator::make($request->all(),[
            'name'=>'required|string|max:255',
            'email'=>'required|string|max:255|unique:users|email',
            'password'=>'required|string|max:6|confirmed',
        ]); 
        if ($validated->fails()) {
           return response()->json($validated->errors(),422);
        }
        try {
            $user = User::create([
                'name'=>$request->name,
                'email'=>$request->email,
                'password'=>Hash::make($request->password)
            ]);
    
            $token = $user->createToken('auth_token')->plainTextToken;
            return response()->json([
                'access_token'=> $token,
                'user'=>$user
            ],200);
        } catch (\Exception $e) {
            return response()->json(['errors'=>$e->getMessage()],500);
        }
        
    }
}
