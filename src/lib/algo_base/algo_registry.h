/*
* (C) 2014,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_ALGO_REGISTRY_H__
#define BOTAN_ALGO_REGISTRY_H__

#include <botan/types.h>
#include <functional>
#include <stdexcept>
#include <mutex>
#include <vector>
#include <map>
#include <unordered_map>

namespace Botan {

size_t static_provider_weight(const std::string& prov_name);

template<typename T>
class Algo_Registry
   {
   public:
      typedef typename T::Spec Spec;

      typedef std::function<T* (const Spec&)> maker_fn;

      static Algo_Registry<T>& global_registry()
         {
         static Algo_Registry<T> g_registry;
         return g_registry;
         }

      void add(const std::string& name, const std::string& provider, maker_fn fn)
         {
         std::unique_lock<std::mutex> lock(m_mutex);

         if(!m_maker_fns[name][provider])
            m_maker_fns[name][provider] = fn;
         }

      std::vector<std::string> providers(const std::string& basename) const
         {
         std::unique_lock<std::mutex> lock(m_mutex);

         std::vector<std::string> v;
         auto i = m_maker_fns.find(basename);
         if(i != m_maker_fns.end())
            {
            for(auto&& prov : i->second)
               v.push_back(prov);
            }
         return v;
         }

      T* make(const Spec& spec, const std::string& provider = "")
         {
         maker_fn maker = find_maker(spec, provider);

         try
            {
            return maker(spec);
            }
         catch(std::exception& e)
            {
            //return nullptr; // ??
            throw std::runtime_error("Creating '" + spec.as_string() + "' failed: " + e.what());
            }
         }

      class Add
         {
         public:
            Add(const std::string& basename, maker_fn fn, const std::string& provider = "builtin")
               {
               Algo_Registry<T>::global_registry().add(basename, provider, fn);
               }

            Add(bool cond, const std::string& basename, maker_fn fn, const std::string& provider)
               {
               if(cond)
                  Algo_Registry<T>::global_registry().add(basename, provider, fn);
               }
         };

   private:
      Algo_Registry() {}

      maker_fn find_maker(const Spec& spec, const std::string& provider)
         {
         const std::string basename = spec.algo_name();

         std::unique_lock<std::mutex> lock(m_mutex);
         auto makers = m_maker_fns.find(basename);

         if(makers != m_maker_fns.end() && !makers->second.empty())
            {
            const auto& providers = makers->second;

            if(provider != "")
               {
               // find one explicit provider requested by user, or fail
               auto i = providers.find(provider);
               if(i != providers.end())
                  return i->second;
               }
            else
               {
               if(providers.size() == 1)
                  {
                  return providers.begin()->second;
                  }
               else if(providers.size() > 1)
                  {
                  // TODO choose best of available options (how?)
                  //throw std::runtime_error("multiple choice not implemented");
                  return providers.begin()->second;
                  }
               }
            }

         // Default result is a function producing a null pointer
         return [](const Spec&) { return nullptr; };
         }

      std::mutex m_mutex;
      std::unordered_map<std::string, std::unordered_map<std::string, maker_fn>> m_maker_fns;
   };

template<typename T> T*
make_a(const typename T::Spec& spec, const std::string provider = "")
   {
   return Algo_Registry<T>::global_registry().make(spec, provider);
   }

template<typename T> T*
make_new_T(const typename Algo_Registry<T>::Spec&) { return new T; }

template<typename T, size_t DEF_VAL> T*
make_new_T_1len(const typename Algo_Registry<T>::Spec& spec)
   {
   return new T(spec.arg_as_integer(0, DEF_VAL));
   }

template<typename T, size_t DEF1, size_t DEF2> T*
make_new_T_2len(const typename Algo_Registry<T>::Spec& spec)
   {
   return new T(spec.arg_as_integer(0, DEF1), spec.arg_as_integer(1, DEF2));
   }

template<typename T> T*
make_new_T_1str(const typename Algo_Registry<T>::Spec& spec, const std::string& def)
   {
   return new T(spec.arg(0, def));
   }

template<typename T> T*
make_new_T_1str_req(const typename Algo_Registry<T>::Spec& spec)
   {
   return new T(spec.arg(0));
   }

template<typename T, typename X> T*
make_new_T_1X(const typename Algo_Registry<T>::Spec& spec)
   {
   std::unique_ptr<X> x(Algo_Registry<X>::global_registry().make(spec.arg(0)));
   if(!x)
      throw std::runtime_error(spec.arg(0));
   return new T(x.release());
   }

#define BOTAN_REGISTER_NAMED_T(T, namestr, type, maker)                 \
   namespace { Algo_Registry<T>::Add g_ ## type ## _reg(namestr, maker); }
#define BOTAN_REGISTER_T(T, name, maker) \
   namespace { Algo_Registry<T>::Add g_ ## name ## _reg(#name, maker); }
#define BOTAN_REGISTER_T_NOARGS(T, name)                                \
   namespace { Algo_Registry<T>::Add g_ ## name ## _reg(#name, make_new_T<name>); }
#define BOTAN_REGISTER_T_1LEN(T, name, def) \
   namespace { Algo_Registry<T>::Add g_ ## name ## _reg(#name, make_new_T_1len<name, def>); }

#define BOTAN_REGISTER_NAMED_T_NOARGS(T, type, name, provider) \
   namespace { Algo_Registry<T>::Add g_ ## type ## _reg(name, make_new_T<type>, provider); }
#define BOTAN_COND_REGISTER_NAMED_T_NOARGS(cond, T, type, name, provider) \
   namespace { Algo_Registry<T>::Add g_ ## type ## _reg(cond, name, make_new_T<type>, provider); }
#define BOTAN_REGISTER_NAMED_T_2LEN(T, type, name, provider, len1, len2)     \
   namespace { Algo_Registry<T>::Add g_ ## type ## _reg(name, make_new_T_2len<type, len1, len2>, provider); }

// TODO move elsewhere:
#define BOTAN_REGISTER_TRANSFORM(name, maker) BOTAN_REGISTER_T(Transform, name, maker)
#define BOTAN_REGISTER_TRANSFORM_NOARGS(name) BOTAN_REGISTER_T_NOARGS(Transform, name)

}

#endif